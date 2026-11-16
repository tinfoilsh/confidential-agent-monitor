package browser

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/accessibility"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	loopback     = "127.0.0.1:0"
	refPrefix    = "e"
	genSeparator = "."
	inputNode    = "INPUT"
	pageType     = "page"
	detachedPage = "Not attached to an active page"
)

var (
	inputs    = []string{"click", "type", "fill"}
	refLine   = regexp.MustCompile(`(?m)^(` + refPrefix + `\d+) `)
	errHeld   = errors.New("the owner paused the agent and is using this browser; try again later")
	errPassed = errors.New("the owner used the browser since this request arrived; take a snapshot again")
	errMoved  = errors.New("the page changed since the snapshot this ref came from; take a snapshot again")
	errClosed = errors.New("the tab closed")
	errDialog = errors.New("the page is showing a dialog; accept or dismiss it")
)

type Browser struct {
	Allocate          func(ctx context.Context, proxy string) (allocator context.Context, cancel context.CancelFunc)
	StartURL          string
	Worker            func(*target.Info) bool
	Proxy             http.Handler
	ServeListener     func(ctx context.Context, ln net.Listener, server *http.Server) error
	ServeHTTP         func(ctx context.Context, conn net.Conn, server *http.Server) error
	Form              func(origin, text string) (name, field string, inputTypes []string, err error)
	Secret            func(ctx context.Context, name string) (string, error)
	Logins            bool
	CommandTimeout    time.Duration
	CaptureTimeout    time.Duration
	MaxBody           int64
	ScreenshotQuality int
}

type Session struct {
	Browser
	life    sync.RWMutex
	cancel  context.CancelFunc
	workers sync.WaitGroup
	root    context.Context
	worker  context.Context
	op      sync.Mutex
	mu      sync.Mutex
	tabs    map[target.ID]*tabState
	order   []target.ID
	held    bool
	epoch   int
	stop    context.CancelFunc
	cleanup []func()
	running *running
	seen    document
	gen     int
}

type tabState struct {
	context context.Context
	close   context.CancelCauseFunc
	dialog  bool
}

type running struct {
	tab       target.ID
	interrupt context.CancelCauseFunc
}

type document struct {
	tab    target.ID
	loader cdp.LoaderID
	epoch  int
}

type request struct {
	URL        string `json:"url"`
	Ref        string `json:"ref"`
	Text       string `json:"text"`
	node       cdp.BackendNodeID
	generation int
	slot       string
}

func (b *Session) start(ctx context.Context) error {
	proxy, err := b.proxy(ctx)
	if err != nil {
		return err
	}
	b.cleanup = append(b.cleanup, func() { proxy.Close() })
	alloc, cancel := b.Allocate(ctx, proxy.Addr().String())
	b.cleanup = append(b.cleanup, cancel)
	tab, cancel := chromedp.NewContext(alloc)
	b.cleanup = append(b.cleanup, cancel)
	if _, err := chromedp.Run(tab, chromedp.Navigate(b.StartURL)); err != nil {
		return err
	}
	targets, err := chromedp.Targets(tab)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if b.Worker(t) {
			b.worker, cancel = chromedp.NewContext(tab, chromedp.WithTargetID(t.TargetID))
			b.cleanup = append(b.cleanup, cancel)
		}
	}
	if b.worker == nil {
		return errors.New("the browser extension did not start")
	}
	if _, err := chromedp.Run(b.worker, chromedp.Evaluate[bool]("true")); err != nil {
		return err
	}
	id := chromedp.FromContext(tab).Target.TargetID
	b.root, b.tabs, b.order = tab, map[target.ID]*tabState{}, []target.ID{id}
	tabCtx, closeTab := context.WithCancelCause(tab)
	b.tabs[id] = &tabState{context: tabCtx, close: closeTab}
	b.watch(tabCtx, id)
	b.workers.Go(func() {
		for e, err := range chromedp.BrowserEvents(tab, target.TargetDestroyed) {
			if err != nil {
				return
			}
			b.mu.Lock()
			if tab := b.tabs[e.TargetID]; tab != nil {
				tab.close(errClosed)
				delete(b.tabs, e.TargetID)
				b.order = slices.DeleteFunc(b.order, func(id target.ID) bool { return id == e.TargetID })
			}
			b.mu.Unlock()
		}
	})
	return nil
}

func (b *Session) close() error {
	b.cancel()
	for i := len(b.cleanup) - 1; i >= 0; i-- {
		b.cleanup[i]()
	}
	b.cleanup = nil
	b.workers.Wait()
	return nil
}

func (b *Session) serve(ctx context.Context, conn net.Conn, gate func(context.Context, facts.Event) error) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /navigate", b.handle(gate, "navigate", b.navigate))
	mux.HandleFunc("GET /snapshot", b.handle(gate, "snapshot", b.snapshot))
	mux.HandleFunc("GET /text", b.handle(gate, "text", b.text))
	mux.HandleFunc("GET /screenshot", b.handle(gate, "screenshot", b.screenshot))
	mux.HandleFunc("POST /click", b.handle(gate, "click", b.click))
	mux.HandleFunc("POST /type", b.handle(gate, "type", b.typeText))
	mux.HandleFunc("POST /fill", b.handle(gate, "fill", b.fill))
	b.ServeHTTP(ctx, conn, &http.Server{Handler: mux})
}

func (b *Session) handle(gate func(context.Context, facts.Event) error, command string, do func(context.Context, request) ([]byte, string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		epoch := b.epoch
		b.mu.Unlock()
		var err error
		var req request
		if r.Method == http.MethodPost {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, b.MaxBody))
			if err == nil {
				err = facts.DecodeNumbers(raw, &req)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if slices.Contains(inputs, command) {
			req.node, req.generation, err = backend(req.Ref)
			if err != nil {
				fail(w, forbidden{err})
				return
			}
		}
		var page string
		if err == nil {
			err = b.within(r, epoch, command, req, func(ctx context.Context, at string, _ document) error {
				page = at
				if u, err := url.Parse(at); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
					return forbidden{fmt.Errorf("%q is not an http or https page", at)}
				}
				var err error
				if req.slot, err = b.secret(ctx, command, req); err != nil {
					return forbidden{err}
				}
				return nil
			})
		}
		if err != nil {
			fail(w, err)
			return
		}
		u, _ := url.Parse(page)
		layer := &BrowserFacts{Command: command, URL: u.String(), Host: strings.ToLower(u.Hostname()), Text: req.Text, Logins: b.Logins}
		if req.slot != "" {
			layer.Secrets = []string{req.slot}
		}
		if err := gate(r.Context(), facts.Capture(layer.Describe(), nil)); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		var body []byte
		var kind string
		err = b.within(r, epoch, command, req, func(ctx context.Context, at string, doc document) error {
			if at != page {
				return fmt.Errorf("%w; it is now %s", errMoved, at)
			}
			var err error
			body, kind, err = do(ctx, req)
			switch {
			case err == nil && command == "snapshot":
				body = b.observe(doc, body)
			case slices.Contains(inputs, command) && delivered(ctx, err):
				err = nil
			}
			return err
		})
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Content-Type", kind)
		w.Write(body)
	}
}

func (b *Session) within(r *http.Request, epoch int, command string, req request, fn func(context.Context, string, document) error) error {
	b.op.Lock()
	defer b.op.Unlock()
	guard, cancel := context.WithCancel(r.Context())
	defer cancel()
	b.mu.Lock()
	held, passed := b.held, b.epoch != epoch
	if !held && !passed {
		b.stop = cancel
	}
	b.mu.Unlock()
	switch {
	case held:
		return errHeld
	case passed:
		return errPassed
	}
	defer func() {
		b.mu.Lock()
		b.stop = nil
		b.mu.Unlock()
	}()
	if err := b.follow(guard, true); err != nil {
		return err
	}
	ctx, done := b.command(guard)
	defer done()
	page, doc, err := b.document(ctx, epoch)
	switch {
	case err != nil:
		return err
	case command == "navigate":
		page = req.URL
	case slices.Contains(inputs, command):
		b.mu.Lock()
		fresh := req.generation == b.gen && doc == b.seen
		b.mu.Unlock()
		if !fresh {
			return fmt.Errorf("%w; it is now %s", errMoved, page)
		}
	}
	if err := fn(ctx, page, doc); err != nil {
		if guard.Err() != nil {
			return fmt.Errorf("%w; the command was interrupted: %v", errHeld, err)
		}
		return err
	}
	return nil
}

func delivered(ctx context.Context, err error) bool {
	var e *cdproto.Error
	cause := context.Cause(ctx)
	return errors.As(err, &e) && e.Message == detachedPage || errors.Is(cause, errClosed) || errors.Is(cause, errDialog)
}

func (b *Session) watch(tab context.Context, id target.ID) {
	b.workers.Go(func() {
		for _, err := range chromedp.Events(tab, page.JavascriptDialogOpening) {
			if err != nil {
				return
			}
			b.mu.Lock()
			if tab := b.tabs[id]; tab != nil {
				tab.dialog = true
			}
			if b.running != nil && b.running.tab == id {
				b.running.interrupt(errDialog)
			}
			b.mu.Unlock()
		}
	})
	b.workers.Go(func() {
		for _, err := range chromedp.Events(tab, page.JavascriptDialogClosed) {
			if err != nil {
				return
			}
			b.mu.Lock()
			if tab := b.tabs[id]; tab != nil {
				tab.dialog = false
			}
			b.mu.Unlock()
		}
	})
}

func (d document) token() string { return fmt.Sprintf("%s.%s.%d", d.tab, d.loader, d.epoch) }

func (b *Session) document(ctx context.Context, epoch int) (string, document, error) {
	frames, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil {
		return "", document{}, err
	}
	f := frames.FrameTree.Frame
	return f.URL + f.URLFragment, document{chromedp.FromContext(ctx).Target.TargetID, f.LoaderID, epoch}, nil
}

func (b *Session) observe(doc document, lines []byte) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if doc != b.seen {
		b.gen, b.seen = b.gen+1, doc
	}
	return refLine.ReplaceAll(lines, fmt.Appendf(nil, "${1}%s%d ", genSeparator, b.gen))
}

func (b *Session) follow(guard context.Context, newest bool) error {
	ctx, cancel := context.WithTimeout(b.root, b.CommandTimeout)
	defer cancel()
	defer context.AfterFunc(guard, cancel)()
	pages, err := b.pages(ctx)
	if err != nil {
		return err
	}
	for _, t := range pages {
		b.mu.Lock()
		known := b.tabs[t.TargetID] != nil
		b.mu.Unlock()
		if known {
			continue
		}
		tab, err := attach(ctx, b.root, t.TargetID)
		if err != nil {
			return err
		}
		b.mu.Lock()
		tabCtx, closeTab := context.WithCancelCause(tab)
		b.tabs[t.TargetID] = &tabState{context: tabCtx, close: closeTab}
		b.watch(tabCtx, t.TargetID)
		if newest {
			b.order = append(b.order, t.TargetID)
		} else {
			b.order = append([]target.ID{t.TargetID}, b.order...)
		}
		b.mu.Unlock()
	}
	b.mu.Lock()
	id, err := b.choose()
	b.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = chromedp.CallBrowser(ctx, target.ActivateTarget, target.ActivateTargetParams{TargetID: id})
	return err
}

func (b *Session) use(id target.ID) {
	if i := slices.Index(b.order, id); i >= 0 {
		b.order = append(slices.Delete(b.order, i, i+1), id)
	}
}

func (b *Session) choose() (target.ID, error) {
	if len(b.order) == 0 {
		return "", errors.New("the browser has no open tab")
	}
	return b.order[len(b.order)-1], nil
}

func attach(ctx, root context.Context, id target.ID) (context.Context, error) {
	tab, _ := chromedp.NewContext(root, chromedp.WithTargetID(id))
	loop, abort := context.WithCancel(tab)
	stop := context.AfterFunc(ctx, abort)
	_, err := chromedp.Run(loop, chromedp.Func(func(context.Context, *chromedp.Target) error { return nil }))
	if !stop() || err != nil {
		abort()
		return nil, cmp.Or(err, ctx.Err())
	}
	return tab, nil
}

func (b *Session) pages(ctx context.Context) ([]*target.Info, error) {
	targets, err := chromedp.Targets(ctx)
	return slices.DeleteFunc(targets, func(t *target.Info) bool { return t.Type != pageType || t.Subtype != "" }), err
}

func (b *Session) command(guard context.Context) (context.Context, context.CancelFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id, _ := b.choose()
	timed, cancel := context.WithTimeout(b.tabs[id].context, b.CommandTimeout)
	ctx, interrupt := context.WithCancelCause(timed)
	r := &running{id, interrupt}
	b.running = r
	stop := context.AfterFunc(guard, cancel)
	return ctx, func() {
		stop()
		cancel()
		b.mu.Lock()
		if b.running == r {
			b.running = nil
		}
		b.mu.Unlock()
	}
}

type forbidden struct{ error }

func fail(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, errHeld) || errors.Is(err, errPassed) || errors.Is(err, errMoved):
		status = http.StatusConflict
	case errors.As(err, new(forbidden)):
		status = http.StatusForbidden
	}
	http.Error(w, err.Error(), status)
}

func (b *Session) secret(ctx context.Context, command string, req request) (string, error) {
	if command != "fill" {
		for _, text := range []string{req.URL, req.Text} {
			if _, _, _, err := b.Form("", text); err != nil {
				return "", err
			}
		}
		return "", nil
	}
	id := req.node
	origin, err := b.frameOrigin(ctx, id)
	if err != nil {
		return "", err
	}
	name, field, types, err := b.Form(origin, req.Text)
	if name == "" || err != nil {
		return "", err
	}
	node, err := chromedp.Call(ctx, dom.DescribeNode, dom.DescribeNodeParams{BackendNodeID: id})
	if err != nil {
		return "", err
	}
	kind := ""
	for i := 0; i+1 < len(node.Node.Attributes); i += 2 {
		if strings.EqualFold(node.Node.Attributes[i], "type") {
			kind = strings.ToLower(node.Node.Attributes[i+1])
		}
	}
	if node.Node.NodeName != inputNode || !slices.Contains(types, kind) {
		return "", fmt.Errorf("%s is not a %s field", req.Ref, field)
	}
	return name, nil
}

func (b *Session) frameOrigin(ctx context.Context, id cdp.BackendNodeID) (string, error) {
	tree, err := chromedp.Call(ctx, accessibility.GetPartialAXTree, accessibility.GetPartialAXTreeParams{BackendNodeID: id})
	if err != nil {
		return "", err
	}
	nodes := map[accessibility.NodeID]*accessibility.Node{}
	var n *accessibility.Node
	for _, node := range tree.Nodes {
		nodes[node.NodeID] = node
		if node.BackendDOMNodeID == id {
			n = node
		}
	}
	for n != nil && n.FrameID == "" {
		n = nodes[n.ParentID]
	}
	frames, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if n == nil || err != nil {
		return "", fmt.Errorf("the frame of e%d is unknown", id)
	}
	for queue := []*page.FrameTree{frames.FrameTree}; len(queue) > 0; queue = queue[1:] {
		if queue[0].Frame.ID == n.FrameID {
			return queue[0].Frame.SecurityOrigin, nil
		}
		queue = append(queue, queue[0].ChildFrames...)
	}
	return "", fmt.Errorf("the frame of e%d is unknown", id)
}

func backend(ref string) (cdp.BackendNodeID, int, error) {
	node, gen, _ := strings.Cut(strings.TrimPrefix(ref, refPrefix), genSeparator)
	id, err := strconv.ParseInt(node, 10, 64)
	g, gerr := strconv.Atoi(gen)
	if err != nil || gerr != nil || !strings.HasPrefix(ref, refPrefix) {
		return 0, 0, fmt.Errorf("%q is not a ref from the snapshot", ref)
	}
	return cdp.BackendNodeID(id), g, nil
}

func (b *Session) navigate(ctx context.Context, req request) ([]byte, string, error) {
	_, err := chromedp.Run(ctx, chromedp.Navigate(req.URL))
	return nil, "", err
}

func (b *Session) click(ctx context.Context, req request) ([]byte, string, error) {
	id := req.node
	if _, err := chromedp.Call(ctx, dom.ScrollIntoViewIfNeeded, dom.ScrollIntoViewIfNeededParams{BackendNodeID: id}); err != nil {
		return nil, "", err
	}
	quads, err := chromedp.Call(ctx, dom.GetContentQuads, dom.GetContentQuadsParams{BackendNodeID: id})
	if err != nil || len(quads.Quads) == 0 {
		return nil, "", fmt.Errorf("%s is not visible", req.Ref)
	}
	q := quads.Quads[0]
	_, err = chromedp.Run(ctx, chromedp.MouseClickXY((q[0]+q[2]+q[4]+q[6])/4, (q[1]+q[3]+q[5]+q[7])/4))
	return nil, "", err
}

func (b *Session) fill(ctx context.Context, req request) ([]byte, string, error) {
	id := req.node
	text := req.Text
	if req.slot != "" {
		if slot, err := b.secret(ctx, "fill", req); slot != req.slot {
			return nil, "", cmp.Or(err, errors.New("the field no longer takes this credential"))
		}
		var err error
		if text, err = b.Secret(ctx, req.slot); err != nil {
			return nil, "", fmt.Errorf("credential %s is unavailable", req.slot)
		}
	}
	if _, err := chromedp.Call(ctx, dom.Focus, dom.FocusParams{BackendNodeID: id}); err != nil {
		return nil, "", err
	}
	node, err := chromedp.Call(ctx, dom.ResolveNode, dom.ResolveNodeParams{BackendNodeID: id})
	if err != nil {
		return nil, "", err
	}
	if _, err := chromedp.Run(ctx, chromedp.CallFunctionOn[any]("function() { this.select?.() }", func(p *runtime.CallFunctionOnParams) {
		p.ObjectID = node.Object.ObjectID
	})); err != nil {
		return nil, "", err
	}
	_, err = chromedp.Call(ctx, input.InsertText, input.InsertTextParams{Text: text})
	return nil, "", err
}

func (b *Session) typeText(ctx context.Context, req request) ([]byte, string, error) {
	id := req.node
	if _, err := chromedp.Call(ctx, dom.Focus, dom.FocusParams{BackendNodeID: id}); err != nil {
		return nil, "", err
	}
	_, err := chromedp.Run(ctx, chromedp.KeyEvent(req.Text))
	return nil, "", err
}

func (b *Session) snapshot(ctx context.Context, _ request) ([]byte, string, error) {
	lines, err := b.call(ctx, "snapshot")
	return []byte(lines), "text/plain; charset=utf-8", err
}

func (b *Session) text(ctx context.Context, _ request) ([]byte, string, error) {
	md, err := b.call(ctx, "text")
	return []byte(md), "text/markdown; charset=utf-8", err
}

func (b *Session) screenshot(ctx context.Context, _ request) ([]byte, string, error) {
	png, err := b.call(ctx, "screenshot")
	if err != nil {
		return nil, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(png)
	return raw, "image/png", err
}

func (b *Session) call(ctx context.Context, function string) (string, error) {
	id := chromedp.FromContext(ctx).Target.TargetID
	worker, cancel := context.WithCancel(b.worker)
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()
	return chromedp.Run(worker, chromedp.Evaluate[string](fmt.Sprintf("%s(%q)", function, id), chromedp.EvalAwaitPromise))
}

func (v *BrowserFacts) Describe() facts.Observation {
	scope := map[string]any{"host": v.Host}
	if len(v.Secrets) > 0 {
		scope["secrets"] = v.Secrets
	}
	op := &facts.Operation{Action: v.Command}
	return facts.Observation{Operation: op, Title: v.Command + " " + v.URL, Parameters: scope, Details: Details{Browser: v}}
}
