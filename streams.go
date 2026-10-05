package main

import (
	"context"

	"github.com/tinfoilsh/monitor/connector"
)

// Connector streams are registered before any connector can consume their data.
// Mailbox channels are separate and remain available after a label changes.
func (m *monitor) trackStream(fingerprint string, s *connector.Stream) error {
	m.flow.Lock()
	defer m.flow.Unlock()
	if _, ok := m.live.Load().principals[fingerprint]; !ok {
		return errNoAgent
	}
	if m.streams == nil {
		m.streams = map[string]map[*connector.Stream]struct{}{}
	}
	if m.streams[fingerprint] == nil {
		m.streams[fingerprint] = map[*connector.Stream]struct{}{}
	}
	m.streams[fingerprint][s] = struct{}{}
	context.AfterFunc(s.Context, func() {
		m.flow.Lock()
		defer m.flow.Unlock()
		delete(m.streams[fingerprint], s)
		if len(m.streams[fingerprint]) == 0 {
			delete(m.streams, fingerprint)
		}
	})
	return nil
}

// retireStreamsLocked requires flow. Closing the client side prevents further
// input under an old authorization, including on raw SSH and CLI streams.
func (m *monitor) retireStreamsLocked(fingerprint string, source *connector.Stream) {
	for s := range m.streams[fingerprint] {
		if s == source {
			continue
		}
		s.Close()
		delete(m.streams[fingerprint], s)
	}
	if len(m.streams[fingerprint]) == 0 {
		delete(m.streams, fingerprint)
	}
}
