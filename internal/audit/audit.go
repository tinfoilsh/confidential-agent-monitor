// Package audit keeps an append-only log of sealed records in immutable bucket segments.
package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"gocloud.dev/blob"
)

// Settled records are batched into immutable segments named by upload time, so
// storage credentials never need delete or overwrite access to the log and a
// UTC time prefix selects segments without an index.
const (
	prefix        = "audit/"
	timeFormat    = "20060102T150405.000000000Z"
	flushInterval = time.Minute
	writeTimeout  = 30 * time.Second
	segmentBytes  = 8 << 20
	maxBacklog    = 64 << 20
	pageRecords   = 200
)

// Sealer encrypts a segment with its key as the associated data.
type Sealer interface {
	Seal(name string, plain []byte) []byte
	Open(name string, sealed []byte) ([]byte, error)
}

type Log[T any] struct {
	Bucket *blob.Bucket
	// flushing serializes uploads and is acquired before mu.
	flushing sync.Mutex
	mu       sync.Mutex
	sealer   Sealer
	pending  []byte // Settled records awaiting upload, as JSON lines.
}

// SealWith must be called before the first Append.
func (l *Log[T]) SealWith(s Sealer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sealer = s
}

// Append queues a settled record for the next segment.
func (l *Log[T]) Append(record T) error {
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	full := len(l.pending) >= segmentBytes
	l.pending = append(append(l.pending, line...), '\n')
	if !full && len(l.pending) >= segmentBytes {
		go l.Flush()
	}
	return nil
}

// Backlogged reports that settled records cannot be written, so new ones should be refused.
func (l *Log[T]) Backlogged() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending) >= maxBacklog
}

// Flush writes queued records as one segment, keeping them queued if the write fails.
func (l *Log[T]) Flush() {
	l.flushing.Lock()
	defer l.flushing.Unlock()
	l.mu.Lock()
	plain, sealer := l.pending, l.sealer
	l.pending = nil
	l.mu.Unlock()
	if len(plain) == 0 {
		return
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(plain)
	w.Close()
	// The key is the associated data, so a segment cannot be renamed or replayed as another object.
	key := prefix + time.Now().UTC().Format(timeFormat) + "-" + rand.Text()
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if err := l.Bucket.WriteAll(ctx, key, sealer.Seal(key, compressed.Bytes()), nil); err != nil {
		log.Printf("audit: %v", err)
		l.mu.Lock()
		l.pending = append(plain, l.pending...)
		l.mu.Unlock()
	}
}

// Run flushes on an interval until ctx ends, then once more.
func (l *Log[T]) Run(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case <-ticker.C:
		case <-ctx.Done():
		}
		l.Flush()
	}
}

// Page visits records older than the segment named by before, newest first, until visit
// has kept a page of them. It returns the segment the next page starts before.
func (l *Log[T]) Page(ctx context.Context, before string, visit func(segment string, record T) bool) (string, error) {
	before = prefix + before
	// Segment names start with their UTC day, so "T" groups them by day.
	days, err := l.list(ctx, prefix, "T")
	if err != nil {
		return "", err
	}
	next, kept := "", 0
	for _, day := range slices.Backward(days) {
		if before != prefix && day > before {
			continue
		}
		segments, err := l.list(ctx, day, "")
		if err != nil {
			return "", err
		}
		for _, key := range slices.Backward(segments) {
			if kept >= pageRecords {
				return next, nil
			}
			if before != prefix && key >= before {
				continue
			}
			records, err := l.read(ctx, key)
			if err != nil {
				return "", err
			}
			next = strings.TrimPrefix(key, prefix)
			for _, record := range slices.Backward(records) {
				if visit(next, record) {
					kept++
				}
			}
		}
	}
	return "", nil
}

func (l *Log[T]) Read(ctx context.Context, segment string) ([]T, error) {
	return l.read(ctx, prefix+segment)
}

func (l *Log[T]) list(ctx context.Context, dir, delimiter string) ([]string, error) {
	keys := []string{}
	items := l.Bucket.List(&blob.ListOptions{Prefix: dir, Delimiter: delimiter})
	for {
		item, err := items.Next(ctx)
		if errors.Is(err, io.EOF) {
			return keys, nil
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, item.Key)
	}
}

func (l *Log[T]) read(ctx context.Context, key string) ([]T, error) {
	l.mu.Lock()
	sealer := l.sealer
	l.mu.Unlock()
	raw, err := l.Bucket.ReadAll(ctx, key)
	if err == nil {
		raw, err = sealer.Open(key, raw)
	}
	var lines *gzip.Reader
	if err == nil {
		lines, err = gzip.NewReader(bytes.NewReader(raw))
	}
	if err != nil {
		return nil, err
	}
	var records []T
	for decoder := json.NewDecoder(lines); ; {
		var r T
		if err := decoder.Decode(&r); errors.Is(err, io.EOF) {
			return records, nil
		} else if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
}
