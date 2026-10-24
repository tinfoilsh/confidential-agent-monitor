package monitor

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
	"time"

	"github.com/tinfoilsh/monitor/internal/store"
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
	auditPageRecords   = 200
)

var errAuditBacklog = errors.New("the monitor cannot write its audit log; requests are refused until storage recovers")

// auditBacklog refuses new decisions while settled ones cannot be written.
func (m *monitor) auditBacklog() error {
	if len(m.audit) >= maxAuditBacklog {
		return errAuditBacklog
	}
	return nil
}

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

// flushAudit writes queued records as one segment, keeping them queued if the write fails.
func (m *monitor) flushAudit() {
	m.flushing.Lock()
	defer m.flushing.Unlock()
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
	if err := store.Bucket.WriteAll(ctx, key, store.Seal(key, compressed.Bytes()), nil); err != nil {
		log.Printf("audit: %v", err)
		m.mu.Lock()
		m.audit = append(plain, m.audit...)
		m.mu.Unlock()
	}
}

// WriteAudit flushes on an interval until ctx ends, then once more.
func (m *monitor) WriteAudit(ctx context.Context) {
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

// auditPage is one page of settled records, newest first.
type auditPage struct {
	Records []recordSummary `json:"records"`
	Next    string          `json:"next,omitempty"`
}

// readAuditPage returns settled records older than the segment named by before, newest first.
// Records still in the live log are skipped, so the page continues where the live log ends.
func (m *monitor) readAuditPage(ctx context.Context, before string) (auditPage, error) {
	before = auditPrefix + before
	m.mu.Lock()
	store, live := m.store, make(map[string]bool, len(m.records))
	for _, record := range m.records {
		live[record.ID] = true
	}
	m.mu.Unlock()
	// Segment names start with their UTC day, so "T" groups them by day.
	days, err := listAudit(ctx, store, auditPrefix, "T")
	if err != nil {
		return auditPage{}, err
	}
	page := auditPage{Records: []recordSummary{}}
	for _, day := range slices.Backward(days) {
		if before != auditPrefix && day > before {
			continue
		}
		segments, err := listAudit(ctx, store, day, "")
		if err != nil {
			return auditPage{}, err
		}
		for _, key := range slices.Backward(segments) {
			if len(page.Records) >= auditPageRecords {
				return page, nil
			}
			if before != auditPrefix && key >= before {
				continue
			}
			records, err := readAudit(ctx, store, key)
			if err != nil {
				return auditPage{}, err
			}
			page.Next = strings.TrimPrefix(key, auditPrefix)
			for _, record := range slices.Backward(records) {
				if !live[record.ID] {
					summary := record.summary()
					summary.Segment = page.Next
					page.Records = append(page.Records, summary)
				}
			}
		}
	}
	page.Next = ""
	return page, nil
}

// readAuditRecord reads one record from a segment.
func (m *monitor) readAuditRecord(ctx context.Context, segment, id string) (*record, error) {
	m.mu.Lock()
	store := m.store
	m.mu.Unlock()
	records, err := readAudit(ctx, store, auditPrefix+segment)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.ID == id {
			return &record, nil
		}
	}
	return nil, errRecordGone
}

func listAudit(ctx context.Context, store store.Store, prefix, delimiter string) ([]string, error) {
	keys := []string{}
	items := store.Bucket.List(&blob.ListOptions{Prefix: prefix, Delimiter: delimiter})
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

func readAudit(ctx context.Context, store store.Store, key string) ([]record, error) {
	raw, err := store.Bucket.ReadAll(ctx, key)
	if err == nil {
		raw, err = store.Open(key, raw)
	}
	var lines *gzip.Reader
	if err == nil {
		lines, err = gzip.NewReader(bytes.NewReader(raw))
	}
	if err != nil {
		return nil, err
	}
	var records []record
	for decoder := json.NewDecoder(lines); ; {
		var r record
		if err := decoder.Decode(&r); errors.Is(err, io.EOF) {
			return records, nil
		} else if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
}
