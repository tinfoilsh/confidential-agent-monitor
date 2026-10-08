package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const (
	messageHost        = "messages.monitor"
	maxMessageBytes    = 64 << 10
	maxMailboxBytes    = 1 << 20
	maxMailboxMessages = 64
)

var (
	errMessagePermission = errors.New("this message channel is not permitted")
	errMailboxFull       = errors.New("the message channel is full")
	errMessageStorage    = errors.New("the mailbox could not be persisted")
)

// Receive assigns a fixed label to each incoming channel. This also protects
// empty reads and backpressure, which disclose information about the queue.
type messageAccess struct {
	Send    []string                `json:"send,omitempty"`
	Receive map[string]messageLimit `json:"receive,omitempty"`
}

type messageLimit struct {
	Audience string `json:"audience"`
	Trust    string `json:"trust"`
}

func (l messageLimit) label() label { return label{Audience: l.Audience, Trust: l.Trust} }

func validateMessageAccess(name string, access *messageAccess, identities map[string]identity) error {
	if access == nil {
		return nil
	}
	for _, peer := range access.Send {
		if _, ok := identities[peer]; !ok || peer == name {
			return fmt.Errorf("identity %s: message recipient %s must be another identity", name, peer)
		}
	}
	for peer, limit := range access.Receive {
		if _, ok := identities[peer]; !ok || peer == name || !limit.label().Valid() {
			return fmt.Errorf("identity %s: incoming message channel %s needs another identity and valid audience and trust", name, peer)
		}
	}
	return nil
}

type agentMessage struct {
	ID      string          `json:"id"`
	From    string          `json:"from"`
	FromKey string          `json:"from_key"`
	To      string          `json:"to"`
	ToKey   string          `json:"to_key"`
	Time    time.Time       `json:"time"`
	Label   label           `json:"label"`
	Body    json.RawMessage `json:"body"`
}

type mailbox struct {
	From     string         `json:"from"`
	To       string         `json:"to"`
	Limit    messageLimit   `json:"limit"`
	Messages []agentMessage `json:"messages"`
	// History retains labels admitted beyond the channel limit while a lattice
	// was off, including after the queue is drained so empty reads stay labeled.
	History *label `json:"history,omitempty"`
}

func (s *state) namedPrincipal(name string) (principal, bool) {
	for _, p := range s.principals {
		if p.Name == name {
			return p, true
		}
	}
	return principal{}, false
}

func channelLimit(from, to principal) (messageLimit, bool) {
	if from.Key == to.Key || from.Messages == nil || to.Messages == nil || !slices.Contains(from.Messages.Send, to.Name) {
		return messageLimit{}, false
	}
	limit, ok := to.Messages.Receive[from.Name]
	return limit, ok && limit.label().Valid()
}

func (s *state) keepsMailbox(box mailbox) bool {
	from, fromOK := s.principals[box.From]
	to, toOK := s.principals[box.To]
	limit, ok := channelLimit(from, to)
	return fromOK && toOK && ok && limit == box.Limit
}

type messageRequest struct {
	Action string
	Peer   string
	ID     string
	Body   json.RawMessage
}

// messageLocked requires flow and mu, also held until the HTTP response is written.
func (m *monitor) messageLocked(ctx context.Context, fingerprint string, req messageRequest) (result any, status int, err error) {
	if err := ctx.Err(); err != nil {
		return nil, http.StatusRequestTimeout, err
	}
	st := m.live.Load()
	p, ok := st.principals[fingerprint]
	peer, peerOK := st.namedPrincipal(req.Peer)
	if !ok || !peerOK {
		return nil, http.StatusForbidden, errMessagePermission
	}
	from, to := p, peer
	if req.Action != "message.send" {
		from, to = peer, p
	}
	limit, ok := channelLimit(from, to)
	if !ok {
		return nil, http.StatusForbidden, errMessagePermission
	}
	original := m.labelLocked(p.Key)
	original.Because = maps.Clone(original.Because)
	// Keep request identity and context even if parsing or policy evaluation fails.
	r := &record{ID: rand.Text(), State: stateAllowed, Time: time.Now(),
		decision: &decision{Facts: &facts.Facts{
			Version: facts.Version, Kind: facts.KindMessage,
			Principal: facts.Principal{Key: p.Key, Name: p.Name}, Account: messageHost, Service: "custom",
			Title: req.Action + " · " + peer.Name, Context: facts.Context{Label: original},
		}, Next: original}}
	defer func() {
		if err != nil {
			r.State, r.Deny = stateRefused, []string{err.Error()}
		}
		m.records.add(r)
	}()
	cause := "message channel " + from.Name + " -> " + to.Name
	d, err := st.decideMessage(ctx, p, peer, original, limit, req, cause)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	r.decision = d
	if err := refusal(d.Deny); err != nil {
		return nil, http.StatusForbidden, err
	}
	key := from.Key + " " + to.Key
	box, exists := m.doc.Mailboxes[key]
	if exists && !st.keepsMailbox(box) {
		return nil, http.StatusForbidden, errMessagePermission
	}
	if !exists {
		box = mailbox{From: from.Key, To: to.Key, Limit: limit}
	}
	observed := limit.label()
	if box.History != nil {
		observed = observed.Observe(*box.History, cause)
	}
	if req.Action != "message.receive" {
		observed = observed.Observe(original, cause)
	}
	changed := false
	if observed.Audience != limit.Audience || observed.Trust != limit.Trust {
		changed = box.History == nil || box.History.Audience != observed.Audience || box.History.Trust != observed.Trust
		box.History = &observed
	}
	d.Next = d.Next.Observe(observed, cause)
	// Only annotate delivered-message provenance after policy has allowed the
	// operation. Owner deny rules must not observe queue contents or occupancy.
	if req.Action == "message.receive" && len(box.Messages) > 0 {
		cause = "message " + box.Messages[0].ID + " from " + from.Name
		if d.Next.Audience != original.Audience {
			d.Next.Because["audience"] = cause
		}
		if d.Next.Trust != original.Trust {
			d.Next.Because["trust"] = cause
		}
	}
	r.Next = d.Next
	m.setLabelLocked(p.Key, d.Next, nil)
	switch req.Action {
	case "message.send":
		n := len(req.Body)
		for _, msg := range box.Messages {
			n += len(msg.Body)
		}
		if len(box.Messages) >= maxMailboxMessages || n > maxMailboxBytes {
			status, err = http.StatusConflict, errMailboxFull
			break
		}
		msg := agentMessage{ID: rand.Text(), From: from.Name, FromKey: from.Key, To: to.Name, ToKey: to.Key,
			Time: time.Now(), Label: d.Next, Body: bytes.Clone(req.Body)}
		box.Messages = append(slices.Clone(box.Messages), msg)
		changed = true
		r.Result = map[string]any{"message_id": msg.ID}
		result, status = map[string]string{"id": msg.ID}, http.StatusCreated
	case "message.receive":
		status = http.StatusOK
		if len(box.Messages) == 0 {
			status = http.StatusNoContent
		} else {
			result = box.Messages[0]
			r.Result = map[string]any{"message_id": box.Messages[0].ID}
		}
	case "message.ack":
		index := slices.IndexFunc(box.Messages, func(msg agentMessage) bool { return msg.ID == req.ID })
		if index >= 0 {
			box.Messages = slices.Delete(slices.Clone(box.Messages), index, index+1)
			changed = true
		}
		status = http.StatusNoContent
	default:
		return nil, http.StatusBadRequest, errors.New("unknown message operation")
	}
	// Commit the label and queue together before releasing any queue observation,
	// including empty/full responses and retries after a failed label write.
	next := m.doc
	if changed {
		next.Mailboxes = maps.Clone(m.doc.Mailboxes)
		if next.Mailboxes == nil {
			next.Mailboxes = map[string]mailbox{}
		}
		if len(box.Messages) == 0 && box.History == nil {
			delete(next.Mailboxes, key)
		} else {
			next.Mailboxes[key] = box
		}
		next.Generation++
	}
	if err := m.commitLocked(ctx, next); err != nil {
		return nil, http.StatusServiceUnavailable, errMessageStorage
	}
	return result, status, err
}

func (s *state) decideMessage(ctx context.Context, p, peer principal, current label, limit messageLimit, req messageRequest, cause string) (*decision, error) {
	var body any
	if len(req.Body) > 0 {
		if err := connector.DecodeNumbers(req.Body, &body); err != nil {
			return nil, err
		}
	}
	from, to := p.Name, peer.Name
	if req.Action != "message.send" {
		from, to = peer.Name, p.Name
	}
	in := input{Principal: p, Account: &namedAccount{Name: messageHost, account: account{Preset: "custom", Contents: limit.Audience, Sends: limit.Audience}}, Access: access{Level: "allow"}, Label: current,
		Request: &parsedMessage{Action: req.Action, Peer: peer.Name, From: from, To: to, ID: req.ID, Body: body, Channel: facts.Label{Audience: limit.Audience, Trust: limit.Trust}, Cause: cause}}
	return evaluateDecision(ctx, s.decision, in)
}

func (m *monitor) messageHandler(fingerprint string) http.Handler {
	mux := http.NewServeMux()
	handle := func(action string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			req := messageRequest{Action: action, Peer: r.URL.Query().Get("from"), ID: r.PathValue("id")}
			if action == "message.send" {
				r.Body = http.MaxBytesReader(w, r.Body, maxMessageBytes+8192)
				raw, err := io.ReadAll(r.Body)
				var send struct {
					To   string          `json:"to"`
					Body json.RawMessage `json:"body"`
				}
				if err != nil || connector.Decode(raw, &send) != nil || len(send.Body) == 0 || len(send.Body) > maxMessageBytes {
					http.Error(w, "send requires to and a JSON body of at most 64 KiB", http.StatusBadRequest)
					return
				}
				req.Peer, req.Body = send.To, send.Body
			}
			m.flow.Lock()
			defer m.flow.Unlock()
			m.mu.Lock()
			defer m.mu.Unlock()
			result, status, err := m.messageLocked(r.Context(), fingerprint, req)
			if err != nil {
				http.Error(w, err.Error(), status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			if result != nil {
				json.NewEncoder(w).Encode(result)
			}
			// Flush while the label and configuration are still locked.
			http.NewResponseController(w).Flush()
		}
	}
	mux.Handle("POST /messages", handle("message.send"))
	mux.Handle("GET /messages", handle("message.receive"))
	mux.Handle("DELETE /messages/{id}", handle("message.ack"))
	return mux
}

// Each HTTP connection serves one request. The deadline closes the SSH channel
// itself because channelConn does not implement socket deadlines.
func (m *monitor) forwardMessages(p principal, nc ssh.NewChannel, port uint32) {
	if port != 80 {
		nc.Reject(ssh.Prohibited, "messages.monitor uses HTTP on port 80 inside the SSH tunnel")
		return
	}
	if _, ok := m.live.Load().principals[p.Key]; !ok {
		nc.Reject(ssh.Prohibited, "identity removed")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	ctx, cancel := context.WithTimeout(context.Background(), readHeaderTimeout)
	defer cancel()
	s := connector.NewStream(ctx)
	s.Conn = channelConn{ch}
	defer s.Close()
	in := connector.NewListener()
	defer in.Close()
	stop := context.AfterFunc(s.Context, func() { in.Close(); s.Close() })
	defer stop()
	server := &http.Server{Handler: m.messageHandler(p.Key), MaxHeaderBytes: 8192,
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext:       func(context.Context, net.Conn) context.Context { return s.Context }}
	server.SetKeepAlivesEnabled(false)
	defer server.Close()
	go in.Hand(s)
	if err := server.Serve(in); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("mailbox HTTP: %v", err)
	}
}

type parsedMessage struct {
	Action  string      `json:"action"`
	Peer    string      `json:"peer"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	ID      string      `json:"id,omitempty"`
	Body    any         `json:"body,omitempty"`
	Channel facts.Label `json:"channel"`
	Cause   string      `json:"cause"`
}

func (r *parsedMessage) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	effect := map[string]string{"message.send": "send", "message.receive": "read", "message.ack": "write"}[r.Action]
	return facts.Facts{Kind: facts.KindMessage, Operation: &facts.Operation{Action: r.Action, Effects: []string{effect}}, Title: r.Action + " · " + r.Peer,
		Parameters: map[string]any{"peer": r.Peer, "id": r.ID, "body": r.Body}, Details: map[string]any{"message": r},
		Context: facts.Context{Observes: r.Channel, Channel: &r.Channel, Sends: r.Channel.Audience, Cause: r.Cause}}, connector.Approval{}, nil
}
