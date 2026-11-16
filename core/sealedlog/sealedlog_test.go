package sealedlog_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/sealedlog"
)

// memory lists keys like a bucket: sorted, or with a delimiter, their distinct prefixes up to it.
type memory struct {
	objects map[string][]byte
	down    bool
}

func (m *memory) storage() sealedlog.Storage {
	return sealedlog.Storage{
		Write: func(_ context.Context, key string, data []byte) error {
			if m.down {
				return errors.New("storage down")
			}
			m.objects[key] = data
			return nil
		},
		Read: func(_ context.Context, key string) ([]byte, error) { return m.objects[key], nil },
		List: func(_ context.Context, prefix, delimiter string) ([]string, error) {
			var keys []string
			for key := range m.objects {
				if rest, ok := strings.CutPrefix(key, prefix); ok {
					if i := strings.Index(rest, delimiter); delimiter != "" && i >= 0 {
						key = prefix + rest[:i+len(delimiter)]
					}
					if !slices.Contains(keys, key) {
						keys = append(keys, key)
					}
				}
			}
			slices.Sort(keys)
			return keys, nil
		},
	}
}

func TestSealedSegmentsSurviveFailedUploadsAndPageNewestFirst(t *testing.T) {
	m := &memory{objects: map[string][]byte{}, down: true}
	seal := func(name string, plain []byte) []byte { return append([]byte(name+"|"), plain...) }
	open := func(name string, sealed []byte) ([]byte, error) {
		plain, ok := bytes.CutPrefix(sealed, []byte(name+"|"))
		if !ok {
			return nil, errors.New("sealed for another name")
		}
		return plain, nil
	}
	var failures int
	log := sealedlog.New(m.storage(), "audit/", sealedlog.Limits{FlushInterval: time.Hour, WriteTimeout: time.Second, SegmentBytes: 1 << 20, MaxBacklog: 8, PageRecords: 2},
		seal, open, func(error) { failures++ })
	log.Append([]byte(`{"id":1}`))
	log.Flush()
	if failures != 1 || len(m.objects) != 0 || !log.Backlogged() {
		t.Fatalf("failed upload dropped records: %d failures, %d objects", failures, len(m.objects))
	}
	m.down = false
	stopped, stop := context.WithCancel(context.Background())
	stop()
	log.Run(stopped)
	if len(m.objects) != 1 || log.Backlogged() {
		t.Fatal("stopping did not flush the pending records")
	}
	log.Append([]byte(`{"id":2}`))
	log.Append([]byte(`{"id":3}`))
	log.Flush()
	if len(m.objects) != 2 || log.Backlogged() {
		t.Fatalf("%d segments", len(m.objects))
	}
	var seen []string
	next, err := log.Page(context.Background(), "", func(_ string, line []byte) bool {
		seen = append(seen, string(line))
		return true
	})
	if err != nil || !slices.Equal(seen, []string{`{"id":3}`, `{"id":2}`}) || next == "" {
		t.Fatalf("page %v next %q: %v", seen, next, err)
	}
	seen = nil
	if _, err := log.Page(context.Background(), next, func(_ string, line []byte) bool { seen = append(seen, string(line)); return true }); err != nil || !slices.Equal(seen, []string{`{"id":1}`}) {
		t.Fatalf("second page %v: %v", seen, err)
	}
	for key, data := range m.objects {
		m.objects[key+"-renamed"] = data
		if _, err := log.Read(context.Background(), strings.TrimPrefix(key, "audit/")+"-renamed"); err == nil {
			t.Fatal("a renamed segment opened")
		}
		break
	}
}
