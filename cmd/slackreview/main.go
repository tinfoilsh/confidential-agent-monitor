package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/slack-go/slack"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/postgres"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/approval"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"golang.org/x/crypto/ssh"
)

const (
	tokenEnv    = "SLACK_BOT_TOKEN"
	secretEnv   = "SLACK_SIGNING_SECRET"
	passwordEnv = "PGPASSWORD"

	approveAction = "approve"
	denyAction    = "deny"
	readAction    = "read"
	// Agents open the database by this name inside the SSH tunnel.
	database = "database"

	stateAllowed    = "allowed"
	statePending    = "pending"
	stateApproved   = "approved"
	stateDenied     = "denied"
	stateUnanswered = "unanswered"
	stateUnsent     = "unsent"

	maxPayload  = 64 << 10
	maxRequests = 1000
	// A Slack section shows at most this much text, and a reviewer must see the whole statement.
	maxReviewText     = 3000
	approvalWait      = 5 * time.Minute
	slackTimeout      = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	dialTimeout       = 10 * time.Second
	connectTimeout    = 30 * time.Second
	openTimeout       = time.Minute
)

var (
	answers   = map[string]string{approveAction: stateApproved, denyAction: stateDenied}
	decisions = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	sshLimits = sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 64, HandshakeTimeout: 10 * time.Second}
)

type request struct {
	id, text  string
	state, by string
}

type reviewer struct {
	slack     *slack.Client
	channel   string
	secret    string
	team      string
	reviewers []string
	mu        sync.Mutex
	requests  *approval.Records[*request]
}

func (r *request) message() []slack.MsgOption {
	plain := func(text string) *slack.TextBlockObject {
		return slack.NewTextBlockObject(slack.PlainTextType, text, false, false)
	}
	button := func(action, label string) slack.BlockElement {
		return slack.NewButtonBlockElement(action, r.id, plain(label))
	}
	blocks := []slack.Block{slack.NewSectionBlock(plain(r.text), nil, nil), slack.NewActionBlock(r.id, button(approveAction, "Approve"), button(denyAction, "Deny"))}
	if r.state != statePending {
		outcome := r.state
		if r.by != "" {
			outcome += " by <@" + r.by + ">"
		}
		blocks[1] = slack.NewContextBlock(r.id, slack.NewTextBlockObject(slack.MarkdownType, outcome, false, false))
	}
	// Plain text and an escaped fallback keep a statement from formatting or mentioning its way into the request.
	return []slack.MsgOption{slack.MsgOptionText(r.text, true), slack.MsgOptionBlocks(blocks...)}
}

func (rv *reviewer) gate(agent string) connector.Gate {
	return func(ctx context.Context, event facts.Event) error {
		o, err := event.Decode()
		if err != nil {
			return err
		}
		r := &request{text: agent + " asks: " + o.Title, state: stateAllowed}
		if o.Operation == nil || o.Operation.Action != readAction {
			err = rv.review(ctx, r)
		}
		decisions.Info("decision", "agent", agent, "operation", o.Title, "state", r.state, "by", r.by)
		return err
	}
}

func (rv *reviewer) review(ctx context.Context, r *request) error {
	if len(r.text) > maxReviewText {
		r.state = stateUnsent
		return errors.New("this statement is too long to review in Slack")
	}
	r.id, r.state = rand.Text(), statePending
	ask := r.message()
	rv.mu.Lock()
	rv.requests.Add(r)
	rv.mu.Unlock()
	_, sent, err := rv.slack.PostMessageContext(ctx, rv.channel, ask...)
	rv.mu.Lock()
	if err != nil {
		r.state = stateUnsent
	}
	for deadline := time.Now().Add(approvalWait); r.state == statePending; {
		if rv.requests.Wait(ctx, deadline) || ctx.Err() != nil {
			r.state = stateUnanswered
		}
	}
	rv.mu.Unlock()
	if err == nil {
		_, _, _, err = rv.slack.UpdateMessage(rv.channel, sent, r.message()...)
	}
	if err != nil {
		log.Printf("slack: request %s: %v", r.id, err)
	}
	if r.state != stateApproved {
		return fmt.Errorf("Slack review of this statement: %s", r.state)
	}
	return nil
}

func (rv *reviewer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	verifier, err := slack.NewSecretsVerifier(r.Header, rv.secret)
	var body []byte
	if err == nil {
		body, err = io.ReadAll(io.TeeReader(http.MaxBytesReader(w, r.Body, maxPayload), &verifier))
	}
	if err == nil {
		err = verifier.Ensure()
	}
	if err != nil {
		http.Error(w, "invalid Slack signature", http.StatusUnauthorized)
		return
	}
	form, err := url.ParseQuery(string(body))
	var callback slack.InteractionCallback
	if err == nil {
		err = json.Unmarshal([]byte(form.Get("payload")), &callback)
	}
	actions := callback.ActionCallback.BlockActions
	if err != nil || callback.Type != slack.InteractionTypeBlockActions || len(actions) != 1 || answers[actions[0].ActionID] == "" {
		http.Error(w, "not a request button", http.StatusBadRequest)
		return
	}
	if callback.Team.ID != rv.team || !slices.Contains(rv.reviewers, callback.User.ID) {
		http.Error(w, "not a reviewer", http.StatusForbidden)
		return
	}
	rv.mu.Lock()
	defer rv.mu.Unlock()
	pending, found := rv.requests.Find(func(p *request) bool { return p.id == actions[0].Value && p.state == statePending })
	if !found {
		http.Error(w, "this request is no longer pending", http.StatusConflict)
		return
	}
	pending.state, pending.by = answers[actions[0].ActionID], callback.User.ID
	rv.requests.Notify()
}

func (rv *reviewer) serve(address, hostKey, agentKeys, target string) error {
	private, err := os.ReadFile(hostKey)
	if err != nil {
		return err
	}
	host, err := ssh.ParsePrivateKey(private)
	if err != nil {
		return err
	}
	authorized, err := os.ReadFile(agentKeys)
	agents := map[string]string{}
	for err == nil && len(bytes.TrimSpace(authorized)) != 0 {
		var key ssh.PublicKey
		var name string
		if key, name, _, authorized, err = ssh.ParseAuthorizedKey(authorized); err == nil {
			agents[ssh.FingerprintSHA256(key)] = cmp.Or(name, ssh.FingerprintSHA256(key))
		}
	}
	if err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]string{"url": target})
	if err != nil {
		return err
	}
	db, err := postgres.Parse(raw)
	if err != nil {
		return err
	}
	password := func(context.Context) (string, error) { return os.Getenv(passwordEnv), nil }
	// The SSH tunnel already protects the stream, so the database is served inside it without TLS.
	plaintext := func(context.Context, string) *tls.Config { return nil }
	table := core.New(
		func(context.Context, facts.Principal, string) bool { return true },
		func(_ context.Context, p facts.Principal, _ core.Request) (core.Watch, error) {
			return func(context.Context, func()) (connector.Gate, bool) { return rv.gate(p.Name), true }, nil
		},
		func(target connector.Target, _ []core.Candidate) (string, bool, bool) { return target.Host, true, true },
		openTimeout)
	defer table.Close()
	table.Stage(database, "tcp", nil, func(context.Context) (connector.Instance, error) {
		return connector.Instance{Serve: db.Handler((&net.Dialer{Timeout: dialTimeout}).DialContext, password, plaintext, connectTimeout)}, nil
	})
	table.Start()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer context.AfterFunc(ctx, func() { listener.Close() })()
	sshtransport.Serve(listener, func() ssh.Signer { return host }, sshLimits, func(_ ssh.ConnMetadata, key ssh.PublicKey) (sshtransport.Session, func() error, error) {
		fingerprint := ssh.FingerprintSHA256(key)
		name, known := agents[fingerprint]
		if !known {
			return nil, nil, errors.New("unknown agent")
		}
		return func(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request) {
			defer context.AfterFunc(ctx, func() { conn.Close() })()
			sshtransport.ServeDirect(channels, requests, table.Open(facts.Principal{Key: fingerprint, Name: name}))
		}, nil, nil
	}, func(err error) { log.Printf("ssh: %v", err) })
	return nil
}

func main() {
	address := flag.String("ssh", "127.0.0.1:2224", "address agents sign in to over SSH")
	hostKey := flag.String("host-key", "", "file holding this Perimeter's SSH host private key")
	agentKeys := flag.String("agents", "", "authorized_keys file; each key signs in the agent its comment names")
	target := flag.String("database", "", "Postgres URL without its password, which "+passwordEnv+" holds; agents reach it as "+database+" inside the SSH tunnel")
	channel := flag.String("channel", "", "Slack channel ID that writes are posted to for review")
	team := flag.String("team", "", "Slack workspace ID whose reviewers may answer")
	reviewers := flag.String("reviewers", "", "comma-separated Slack user IDs that may answer")
	listen := flag.String("listen", "", "address serving Slack's interactivity requests")
	flag.Parse()
	rv := &reviewer{slack: slack.New(os.Getenv(tokenEnv), slack.OptionHTTPClient(&http.Client{Timeout: slackTimeout})), channel: *channel, secret: os.Getenv(secretEnv), team: *team, reviewers: strings.Split(*reviewers, ",")}
	rv.requests = approval.NewRecords(&rv.mu, maxRequests, func(r *request) bool { return r.state == statePending })
	go func() {
		log.Fatal((&http.Server{Addr: *listen, Handler: rv, ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe())
	}()
	if err := rv.serve(*address, *hostKey, *agentKeys, *target); err != nil {
		log.Fatal(err)
	}
}
