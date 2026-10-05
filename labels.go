package main

import (
	"context"
	"maps"
	"slices"

	"github.com/tinfoilsh/monitor/connector"
)

var cleanLabel = label{Trust: "trusted", Audience: "anyone"}

type label struct {
	Trust    string            `json:"trust"`
	Audience string            `json:"audience"`
	Because  map[string]string `json:"because,omitempty"`
}

func validLabel(l label) bool {
	return slices.Contains(audiences, l.Audience) && slices.Contains(trusts, l.Trust)
}

func (m *monitor) label(fingerprint string) label {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.labelLocked(fingerprint)
}

// labelLocked requires mu.
func (m *monitor) labelLocked(fingerprint string) label {
	if l, ok := m.doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
}

// setLabelLocked requires flow and mu. Keep the new label in memory even if
// persistence fails. The stream observing the data may finish its own request.
func (m *monitor) setLabelLocked(fingerprint string, l label, source *connector.Stream) {
	old := m.labelLocked(fingerprint)
	changed := old.Trust != l.Trust || old.Audience != l.Audience
	if !changed && maps.Equal(old.Because, l.Because) {
		return
	}
	if m.doc.Labels == nil {
		m.doc.Labels = map[string]label{}
	}
	l.Because = maps.Clone(l.Because)
	m.doc.Labels[fingerprint] = l
	m.doc.Generation++
	m.labelsDirty = true
	if changed {
		m.retireStreamsLocked(fingerprint, source)
	}
}

// relabel requires flow. Retry a failed label write before admitting more data,
// including when this request would leave the in-memory label unchanged.
func (m *monitor) relabel(ctx context.Context, fingerprint string, l label, source *connector.Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLabelLocked(fingerprint, l, source)
	if !m.labelsDirty {
		return nil
	}
	return m.commitLocked(ctx, m.doc)
}
