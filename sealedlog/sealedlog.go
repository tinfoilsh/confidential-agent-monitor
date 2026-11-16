// Package sealedlog keeps an append-only log of sealed records in immutable storage segments.
package sealedlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

// Settled records are batched into immutable segments named by upload time, so
// storage credentials never need delete or overwrite access to the log and a
// UTC time prefix selects segments without an index.
const segmentTimeFormat = "20060102T150405.000000000Z"

// Storage holds the segments. List returns the keys under prefix, or with a delimiter the
// distinct prefixes up to it, in ascending order.
type Storage struct {
	Write func(ctx context.Context, key string, data []byte) error
	Read  func(ctx context.Context, key string) ([]byte, error)
	List  func(ctx context.Context, prefix, delimiter string) ([]string, error)
}

type Limits struct {
	FlushInterval, WriteTimeout time.Duration
	// SegmentBytes starts an upload; MaxBacklog is the queue size Backlogged reports.
	SegmentBytes, MaxBacklog int
	// PageRecords is how many records Page keeps.
	PageRecords int
}

type Log struct {
	storage Storage
	prefix  string
	limits  Limits
	seal    func(name string, plain []byte) []byte
	open    func(name string, sealed []byte) ([]byte, error)
	failed  func(error)
	// flushing serializes uploads and is acquired before mu.
	flushing sync.Mutex
	mu       sync.Mutex
	pending  []byte // Settled records awaiting upload, one per line.
}

// New keeps segments under prefix, sealed with seal and opened with open; failed reports uploads that failed.
func New(storage Storage, prefix string, limits Limits, seal func(name string, plain []byte) []byte, open func(name string, sealed []byte) ([]byte, error), failed func(error)) *Log {
	return &Log{storage: storage, prefix: prefix, limits: limits, seal: seal, open: open, failed: failed}
}

// Append queues a settled record, one line without a newline, for the next segment.
func (l *Log) Append(line []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	full := len(l.pending) >= l.limits.SegmentBytes
	l.pending = append(append(l.pending, line...), '\n')
	if !full && len(l.pending) >= l.limits.SegmentBytes {
		go l.Flush()
	}
}

// Backlogged reports that the records awaiting upload have reached MaxBacklog.
func (l *Log) Backlogged() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending) >= l.limits.MaxBacklog
}

// Flush keeps its immutable prefix queued until upload succeeds, so the backlog
// also counts records waiting on storage. Appends may extend the queue.
func (l *Log) Flush() {
	l.flushing.Lock()
	defer l.flushing.Unlock()
	l.mu.Lock()
	plain := l.pending
	l.mu.Unlock()
	if len(plain) == 0 {
		return
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(plain)
	w.Close()
	// The key is the associated data, so a segment cannot be renamed or replayed as another object.
	key := l.prefix + time.Now().UTC().Format(segmentTimeFormat) + "-" + rand.Text()
	ctx, cancel := context.WithTimeout(context.Background(), l.limits.WriteTimeout)
	defer cancel()
	if err := l.storage.Write(ctx, key, l.seal(key, compressed.Bytes())); err != nil {
		l.failed(err)
		return
	}
	l.mu.Lock()
	// Preserve appends during upload.
	l.pending = bytes.Clone(l.pending[len(plain):])
	if len(l.pending) >= l.limits.SegmentBytes {
		go l.Flush()
	}
	l.mu.Unlock()
}

// Run flushes on an interval until ctx ends, then once more.
func (l *Log) Run(ctx context.Context) {
	ticker := time.NewTicker(l.limits.FlushInterval)
	defer ticker.Stop()
	defer l.Flush()
	for {
		select {
		case <-ticker.C:
			l.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// Page visits records older than the segment named by before, newest first, until visit
// has kept a page of them. It returns the segment the next page starts before.
func (l *Log) Page(ctx context.Context, before string, visit func(segment string, line []byte) bool) (string, error) {
	before = l.prefix + before
	// Segment names start with their UTC day, so "T" groups them by day.
	days, err := l.storage.List(ctx, l.prefix, "T")
	if err != nil {
		return "", err
	}
	next, kept := "", 0
	for _, day := range slices.Backward(days) {
		if before != l.prefix && day > before {
			continue
		}
		segments, err := l.storage.List(ctx, day, "")
		if err != nil {
			return "", err
		}
		for _, key := range slices.Backward(segments) {
			if kept >= l.limits.PageRecords {
				return next, nil
			}
			if before != l.prefix && key >= before {
				continue
			}
			lines, err := l.read(ctx, key)
			if err != nil {
				return "", err
			}
			next = strings.TrimPrefix(key, l.prefix)
			for _, line := range slices.Backward(lines) {
				if visit(next, line) {
					kept++
				}
			}
		}
	}
	return "", nil
}

func (l *Log) Read(ctx context.Context, segment string) ([][]byte, error) {
	return l.read(ctx, l.prefix+segment)
}

func (l *Log) read(ctx context.Context, key string) ([][]byte, error) {
	raw, err := l.storage.Read(ctx, key)
	if err == nil {
		raw, err = l.open(key, raw)
	}
	var plain *gzip.Reader
	if err == nil {
		plain, err = gzip.NewReader(bytes.NewReader(raw))
	}
	if err != nil {
		return nil, err
	}
	defer plain.Close()
	records, err := io.ReadAll(plain)
	if err != nil {
		return nil, err
	}
	return bytes.Split(bytes.TrimSuffix(records, []byte("\n")), []byte("\n")), nil
}
