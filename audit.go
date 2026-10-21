package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"gocloud.dev/blob"
)

// Settled records are batched into immutable segments named by upload time, so
// storage credentials never need delete or overwrite access to the log and a
// UTC time prefix selects segments without an index.
const (
	auditPrefix        = "audit/"
	auditTimeFormat    = "20060102T150405.000000000Z"
	auditFlushInterval = time.Minute
	auditWriteTimeout  = 30 * time.Second
	auditSegmentBytes  = 8 << 20
	maxAuditBacklog    = 64 << 20
)

var errAuditBacklog = errors.New("the monitor cannot write its audit log; requests are refused until storage recovers")

// queueAudit is called under mu once a record's outcome is final.
func (m *monitor) queueAudit(r *record) {
	line, err := json.Marshal(r)
	if err != nil {
		log.Printf("audit record %s: %v", r.ID, err)
		return
	}
	full := len(m.audit) >= auditSegmentBytes
	m.audit = append(append(m.audit, line...), '\n')
	if !full && len(m.audit) >= auditSegmentBytes {
		go m.flushAudit()
	}
}

// flushAudit writes the queued records as one segment, keeping them queued if the write fails.
func (m *monitor) flushAudit() {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	m.mu.Lock()
	plain, store := m.audit, m.store
	m.audit = nil
	m.mu.Unlock()
	if len(plain) == 0 {
		return
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(plain)
	w.Close()
	// The key is the associated data, so a segment cannot be renamed or replayed as another object.
	key := auditPrefix + time.Now().UTC().Format(auditTimeFormat) + "-" + rand.Text()
	ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()
	if err := store.bucket.WriteAll(ctx, key, store.aead.Seal(nil, nil, compressed.Bytes(), []byte(key)), nil); err != nil {
		log.Printf("audit: %v", err)
		m.mu.Lock()
		m.audit = append(plain, m.audit...)
		m.mu.Unlock()
	}
}

// writeAudit flushes on an interval until ctx ends, then once more.
func (m *monitor) writeAudit(ctx context.Context) {
	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case <-ticker.C:
		case <-ctx.Done():
		}
		m.flushAudit()
	}
}

// auditSegments lists the segments whose names start with a UTC time prefix, such as 20261020T15.
func (m *monitor) auditSegments(r *http.Request, _ struct{}) (any, error) {
	names := []string{}
	items := m.store.bucket.List(&blob.ListOptions{Prefix: auditPrefix + r.URL.Query().Get("prefix")})
	for {
		item, err := items.Next(r.Context())
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		names = append(names, strings.TrimPrefix(item.Key, auditPrefix))
	}
}

// auditSegment serves one segment's records as JSON lines.
func (m *monitor) auditSegment(w http.ResponseWriter, r *http.Request) {
	key := auditPrefix + r.PathValue("segment")
	raw, err := m.store.bucket.ReadAll(r.Context(), key)
	if err == nil {
		raw, err = m.store.aead.Open(nil, nil, raw, []byte(key))
	}
	var records *gzip.Reader
	if err == nil {
		records, err = gzip.NewReader(bytes.NewReader(raw))
	}
	if err != nil {
		responseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := io.Copy(w, records); err != nil {
		panic(http.ErrAbortHandler)
	}
}
