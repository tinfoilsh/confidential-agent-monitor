package monitor

import (
	"crypto/rand"
	"slices"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
)

const maxRecords = 1000

// record extends an authorization result with application-owned proposal edits.
// Embedding preserves the deployed activity/audit representation.
type record struct {
	*authz.Record
	Changes []config.Change `json:"changes,omitempty"`
}

// addRecord and findRecord run under mu. This is the single collection for both
// gated operations and proposals; pending records cannot be evicted.
func (m *Monitor) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), authz.StateAllowed
	for len(m.records) >= maxRecords {
		i := slices.IndexFunc(m.records, func(r *record) bool { return r.State != authz.StatePending })
		if i < 0 {
			break
		}
		m.records = slices.Delete(m.records, i, i+1)
	}
	m.records = append(m.records, r)
	return r
}

func (m *Monitor) findRecord(id string) *record {
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return nil
	}
	return m.records[i]
}

func (s gateStore) Add(r *authz.Record) { s.m.addRecord(&record{Record: r}) }
