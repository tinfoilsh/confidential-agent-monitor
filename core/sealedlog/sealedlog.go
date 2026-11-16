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

const segmentTimeFormat = "20060102T150405.000000000Z"

type Storage struct {
	Write func(ctx context.Context, key string, data []byte) error
	Read  func(ctx context.Context, key string) ([]byte, error)
	List  func(ctx context.Context, prefix, delimiter string) ([]string, error)
}

type Limits struct {
	FlushInterval, WriteTimeout time.Duration
	SegmentBytes, MaxBacklog    int
	PageRecords                 int
}

type Log struct {
	storage  Storage
	prefix   string
	limits   Limits
	seal     func(name string, plain []byte) []byte
	open     func(name string, sealed []byte) ([]byte, error)
	failed   func(error)
	flushing sync.Mutex
	mu       sync.Mutex
	pending  []byte
}

func New(storage Storage, prefix string, limits Limits, seal func(name string, plain []byte) []byte, open func(name string, sealed []byte) ([]byte, error), failed func(error)) *Log {
	return &Log{storage: storage, prefix: prefix, limits: limits, seal: seal, open: open, failed: failed}
}

func (l *Log) Append(line []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	full := len(l.pending) >= l.limits.SegmentBytes
	l.pending = append(append(l.pending, line...), '\n')
	if !full && len(l.pending) >= l.limits.SegmentBytes {
		go l.Flush()
	}
}

func (l *Log) Backlogged() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending) >= l.limits.MaxBacklog
}

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
	key := l.prefix + time.Now().UTC().Format(segmentTimeFormat) + "-" + rand.Text()
	ctx, cancel := context.WithTimeout(context.Background(), l.limits.WriteTimeout)
	defer cancel()
	if err := l.storage.Write(ctx, key, l.seal(key, compressed.Bytes())); err != nil {
		l.failed(err)
		return
	}
	l.mu.Lock()
	l.pending = bytes.Clone(l.pending[len(plain):])
	if len(l.pending) >= l.limits.SegmentBytes {
		go l.Flush()
	}
	l.mu.Unlock()
}

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

func (l *Log) Page(ctx context.Context, before string, visit func(segment string, line []byte) bool) (string, error) {
	before = l.prefix + before
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
