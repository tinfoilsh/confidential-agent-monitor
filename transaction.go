package main

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

// A transaction serializes authorization state: configuration publication,
// observations, approval records, and stream retirement. Evaluation
// runs inside the transaction; approval waits release it.
type transaction monitor

func (m *monitor) transact(fn func(*transaction) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn((*transaction)(m))
}

func (tx *transaction) record(d *decision) *record {
	r := &record{ID: rand.Text(), Time: time.Now(), State: stateAllowed, decision: d}
	tx.records = append(tx.records, r)
	if len(tx.records) > maxRecords {
		tx.records = tx.records[1:]
	}
	return r
}

func (tx *transaction) finish(r *record, err error) error {
	if err != nil && r.State != stateDenied && r.State != stateExpired {
		r.State = stateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
	return err
}

// observe persists restrictive labels before releasing data, retrying failed writes.
func (tx *transaction) observe(ctx context.Context, key string, nextLabel facts.Label, source *connector.Stream) error {
	tx.setLabel(key, nextLabel, source)
	if !tx.labelsDirty {
		return nil
	}
	return tx.commit(ctx, tx.doc)
}
