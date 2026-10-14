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
	"github.com/elazarl/goproxy"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

func Definition(extension string, sandboxed bool) connector.Definition {
	return connector.Definition{Settings: &extension, NewConfig: func() connector.Server {
		return &Browser{Extension: extension, NoSandbox: sandboxed}
	}, Requests: []connector.Request{new(Request)}}
}

const (
	loopback     = "127.0.0.1:0"
	extensionURL = "chrome-extension://"
	workerType   = "service_worker"
	startPage    = "about:blank"
	refPrefix    = "e"
	genSeparator = "."
	inputNode    = "INPUT"
	pageType     = "page"
	detachedPage = "Not attached to an active page"
	// A slow page or a busy renderer fails the command rather than holding the browser from the owner.
	commandTimeout = 30 * time.Second
)

var (
	// inputs act on a ref, which must come from a snapshot of the document still showing.
	inputs    = []string{"click", "type", "fill"}
	refLine   = regexp.MustCompile(`(?m)^(` + refPrefix + `\d+) `)
	errHeld   = errors.New("the owner paused the agent and is using this browser; try again later")
	errPassed = errors.New("the owner used the browser since this request arrived; take a snapshot again")
	errMoved  = errors.New("the page changed since the snapshot this ref came from; take a snapshot again")
	errClosed = errors.New("the tab closed")
	errDialog = errors.New("the page is showing a dialog; accept or dismiss it")
)

// Browser drives one Chromium, a tab at a time, with the english-only extension loaded, so the agent sees only censored pages.
// The agent fills a form slot's placeholder; the monitor types the value into a field on the slot's origin.
// The owner may pause the agent and use the browser themselves, then return it with the same session and tabs.
type Browser struct {
	web.Credentials
	Extension string          `json:"-"`
	NoSandbox bool            `json:"-"`
	root      context.Context // The first tab, which owns the browser.
	worker    context.Context
	// op serializes commands on the browser. mu guards the fields below and is never held across a browser call.
	op      sync.Mutex
	mu      sync.Mutex
	tabs    map[target.ID]*tabState
	order   []target.ID // From least to most recently used; the last is the active tab.
	held    bool
	epoch   int                // Changes whenever control passes.
	stop    context.CancelFunc // Ends the agent's command in progress.
	running *running           // The command in progress on a tab, which a dialog the tab opens ends.
	seen    document           // The document of the latest snapshot, whose refs carry gen.
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
	URL  string `json:"url"`
	Ref  string `json:"ref"`
	Text string `json:"text"`
	// connection names the placeholders; slot is the form slot a fill's placeholder names.
	node       cdp.BackendNodeID
	generation int
	connection string
	slot       *web.Slot
}

func (b *Browser) UnmarshalJSON(raw []byte) error {
	type plain Browser
	if err := facts.DecodeNumbers(raw, (*plain)(b)); err != nil {
		return err
	}
	return b.Validate(true)
}

func (b *Browser) Run(ctx context.Context, e *connector.Env, serve func(context.Context)) error {
	proxy, err := b.proxy(e)
	if err != nil {
		return err
	}
	defer proxy.Close()
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	if b.NoSandbox {
		options = append(options, chromedp.NoSandbox)
	}
	alloc, cancel := chromedp.NewExecAllocator(ctx, append(options,
		chromedp.ProxyServer("http://"+proxy.Addr().String()),
		chromedp.Flag("proxy-bypass-list", "<-loopback>"),
		chromedp.Flag("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
		chromedp.Flag("disable-extensions", false),
		chromedp.Flag("load-extension", b.Extension),
		chromedp.Flag("disable-extensions-except", b.Extension),
	)...)
	defer cancel()
	tab, cancel := chromedp.NewContext(alloc)
	defer cancel()
	if _, err := chromedp.Run(tab, chromedp.Navigate(startPage)); err != nil {
		return err
	}
	targets, err := chromedp.Targets(tab)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.Type == workerType && strings.HasPrefix(t.URL, extensionURL) {
			b.worker, cancel = chromedp.NewContext(tab, chromedp.WithTargetID(t.TargetID))
			defer cancel()
		}
	}
	if b.worker == nil {
		return errors.New("the english-only extension did not start")
	}
	// An attached session keeps the service worker from idling out and taking its target with it.
	if _, err := chromedp.Run(b.worker, chromedp.Evaluate[bool]("true")); err != nil {
		return err
	}
	id := chromedp.FromContext(tab).Target.TargetID
	b.root, b.tabs, b.order = tab, map[target.ID]*tabState{}, []target.ID{id}
	tabCtx, closeTab := context.WithCancelCause(tab)
	b.tabs[id] = &tabState{context: tabCtx, close: closeTab}
	b.watch(tabCtx, id)
	// Chrome does not answer input to a tab that the input closes, so a closed tab ends its commands.
	go func() {
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
	}()
	serve(tab)
	return nil
}

func (b *Browser) Serve(s *connector.Stream, _ *connector.Env) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /navigate", b.handle(s, "navigate", b.navigate))
	mux.HandleFunc("GET /snapshot", b.handle(s, "snapshot", b.snapshot))
	mux.HandleFunc("GET /text", b.handle(s, "text", b.text))
	mux.HandleFunc("GET /screenshot", b.handle(s, "screenshot", b.screenshot))
	mux.HandleFunc("POST /click", b.handle(s, "click", b.click))
	mux.HandleFunc("POST /type", b.handle(s, "type", b.typeText))
	mux.HandleFunc("POST /fill", b.handle(s, "fill", b.fill))
	connector.ServeHTTP(s, s, mux)
}

// proxy sends the browser's traffic through the monitor's dialer, so it reaches only allowed networks.
func (b *Browser) proxy(e *connector.Env) (net.Listener, error) {
	ln, err := net.Listen("tcp", loopback)
	if err != nil {
		return nil, err
	}
	p := goproxy.NewProxyHttpServer()
	p.Tr = e.Transport()
	p.ConnectDialWithReq = func(r *http.Request, network, addr string) (net.Conn, error) {
		return e.Dialer.DialContext(r.Context(), network, addr)
	}
	go http.Serve(ln, p)
	return ln, nil
}

// handle gates each command on the page it acts on; one tab serves every request in turn.
// The browser is free while the policy decides, so the command runs only if control did not pass and the page did not move meanwhile.
func (b *Browser) handle(stream *connector.Stream, command string, do func(context.Context, request) ([]byte, string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		epoch := b.epoch
		b.mu.Unlock()
		var err error
		var req request
		if r.Method == http.MethodPost {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
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
		req.connection = stream.Name
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
		layer := &Request{Command: command, URL: u.String(), Host: strings.ToLower(u.Hostname()), Text: req.Text}
		if req.slot != nil {
			layer.Secrets = []string{req.slot.Value}
		}
		if err := stream.Gate(layer); err != nil {
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

// within runs fn on the active tab for an agent command, with the page it acts on: the destination of navigate,
// otherwise the tab's document. Input must name a ref from a snapshot of that document since control last passed.
// A pause ends fn through its context.
func (b *Browser) within(r *http.Request, epoch int, command string, req request, fn func(context.Context, string, document) error) error {
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

// delivered tells whether input that failed reached the page anyway: it started a navigation, which detached the page it went to,
// it closed the tab, or it opened a dialog.
func delivered(ctx context.Context, err error) bool {
	var e *cdproto.Error
	cause := context.Cause(ctx)
	return errors.As(err, &e) && e.Message == detachedPage || errors.Is(cause, errClosed) || errors.Is(cause, errDialog)
}

// watch notes the dialogs a tab opens and closes, until the tab closes. Chrome answers no input to a page showing a dialog,
// so a dialog ends the command in progress on its tab; the dialog stays for the owner to close.
func (b *Browser) watch(tab context.Context, id target.ID) {
	go func() {
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
	}()
	go func() {
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
	}()
}

func (d document) token() string { return fmt.Sprintf("%s.%s.%d", d.tab, d.loader, d.epoch) }

// document identifies the tab's current document; a reload or new page gets a new loader even at the same URL.
func (b *Browser) document(ctx context.Context, epoch int) (string, document, error) {
	frames, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil {
		return "", document{}, err
	}
	f := frames.FrameTree.Frame
	return f.URL + f.URLFragment, document{chromedp.FromContext(ctx).Target.TargetID, f.LoaderID, epoch}, nil
}

// observe numbers a snapshot's refs with its document's generation, so a ref acts on no other document and not after control passes.
func (b *Browser) observe(doc document, lines []byte) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if doc != b.seen {
		b.gen, b.seen = b.gen+1, doc
	}
	return refLine.ReplaceAll(lines, fmt.Appendf(nil, "${1}%s%d ", genSeparator, b.gen))
}

// follow takes in the tabs the browser opened, under op, so a look at the browser never changes
// which tab a command acts on. For the agent the newest tab becomes active, so a popup takes over from its opener;
// for the owner the active tab stays until they pick another. Closing the active tab returns to the one used before it.
func (b *Browser) follow(guard context.Context, newest bool) error {
	ctx, cancel := context.WithTimeout(b.root, commandTimeout)
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
		// The owner has not used a tab the page opened; it waits until they pick it.
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
	// A real browser brings the tab it switches to forward; the page sees itself as visible.
	_, err = chromedp.CallBrowser(ctx, target.ActivateTarget, target.ActivateTargetParams{TargetID: id})
	return err
}

// use makes a tab the most recently used, which choose picks; it requires mu.
func (b *Browser) use(id target.ID) {
	if i := slices.Index(b.order, id); i >= 0 {
		b.order = append(slices.Delete(b.order, i, i+1), id)
	}
}

// choose is the active tab: the most recently used open one. It requires mu.
func (b *Browser) choose() (target.ID, error) {
	if len(b.order) == 0 {
		return "", errors.New("the browser has no open tab")
	}
	return b.order[len(b.order)-1], nil
}

// attach opens a context for a tab. The first command on a tab runs its event loop for as long as that command's context
// lives, so it runs on a context that stays with the tab, which ends only if attaching fails or ctx ends first.
// Tabs hang off the first, which lives as long as the browser; a closed tab's context ends with it.
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

// pages lists the browser's tabs.
func (b *Browser) pages(ctx context.Context) ([]*target.Info, error) {
	targets, err := chromedp.Targets(ctx)
	return slices.DeleteFunc(targets, func(t *target.Info) bool { return t.Type != pageType || t.Subtype != "" }), err
}

// command bounds one command on the active tab and ends it with guard, or when the tab opens a dialog.
func (b *Browser) command(guard context.Context) (context.Context, context.CancelFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id, _ := b.choose()
	timed, cancel := context.WithTimeout(b.tabs[id].context, commandTimeout)
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

// forbidden is a refusal of the command itself, as the policy's are.
type forbidden struct{ error }

// fail reports the owner's control and a moved page as conflicts, so the agent knows to wait or read again.
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

// secret finds the form slot a fill's placeholder names. The field's own frame must hold the slot's origin and its input type must suit the value;
// a placeholder anywhere else is refused.
func (b *Browser) secret(ctx context.Context, command string, req request) (*web.Slot, error) {
	if command != "fill" {
		for _, text := range []string{req.URL, req.Text} {
			if _, err := b.Form(req.connection, "", text); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	id := req.node
	origin, err := b.frameOrigin(ctx, id)
	if err != nil {
		return nil, err
	}
	slot, err := b.Form(req.connection, origin, req.Text)
	if slot == nil || err != nil {
		return nil, err
	}
	node, err := chromedp.Call(ctx, dom.DescribeNode, dom.DescribeNodeParams{BackendNodeID: id})
	if err != nil {
		return nil, err
	}
	kind := ""
	for i := 0; i+1 < len(node.Node.Attributes); i += 2 {
		if strings.EqualFold(node.Node.Attributes[i], "type") {
			kind = strings.ToLower(node.Node.Attributes[i+1])
		}
	}
	if node.Node.NodeName != inputNode || !slices.Contains(web.FormTypes[slot.Form], kind) {
		return nil, fmt.Errorf("%s is not a %s field", req.Ref, slot.Form)
	}
	return slot, nil
}

// frameOrigin reads the node's document from its accessibility ancestors, which the page cannot alter.
func (b *Browser) frameOrigin(ctx context.Context, id cdp.BackendNodeID) (string, error) {
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

// backend reads a snapshot ref such as e42.3: node 42 of the document of generation 3.
func backend(ref string) (cdp.BackendNodeID, int, error) {
	node, gen, _ := strings.Cut(strings.TrimPrefix(ref, refPrefix), genSeparator)
	id, err := strconv.ParseInt(node, 10, 64)
	g, gerr := strconv.Atoi(gen)
	if err != nil || gerr != nil || !strings.HasPrefix(ref, refPrefix) {
		return 0, 0, fmt.Errorf("%q is not a ref from the snapshot", ref)
	}
	return cdp.BackendNodeID(id), g, nil
}

func (b *Browser) navigate(ctx context.Context, req request) ([]byte, string, error) {
	_, err := chromedp.Run(ctx, chromedp.Navigate(req.URL))
	return nil, "", err
}

// click presses the mouse at the centre of the node's first box, as a person would.
func (b *Browser) click(ctx context.Context, req request) ([]byte, string, error) {
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

// fill replaces the field's text, with the slot's value in place of its placeholder.
func (b *Browser) fill(ctx context.Context, req request) ([]byte, string, error) {
	id := req.node
	text := req.Text
	if req.slot != nil {
		// The page may have changed while the owner decided.
		if slot, err := b.secret(ctx, "fill", req); slot != req.slot {
			return nil, "", cmp.Or(err, errors.New("the field no longer takes this credential"))
		}
		var err error
		if text, err = b.Secrets[req.slot.Value].Value(ctx); err != nil {
			return nil, "", fmt.Errorf("credential %s is unavailable", req.slot.Value)
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

// typeText presses keys in the ref's element.
func (b *Browser) typeText(ctx context.Context, req request) ([]byte, string, error) {
	id := req.node
	if _, err := chromedp.Call(ctx, dom.Focus, dom.FocusParams{BackendNodeID: id}); err != nil {
		return nil, "", err
	}
	_, err := chromedp.Run(ctx, chromedp.KeyEvent(req.Text))
	return nil, "", err
}

func (b *Browser) snapshot(ctx context.Context, _ request) ([]byte, string, error) {
	lines, err := b.call(ctx, "snapshot")
	return []byte(lines), "text/plain; charset=utf-8", err
}

func (b *Browser) text(ctx context.Context, _ request) ([]byte, string, error) {
	md, err := b.call(ctx, "text")
	return []byte(md), "text/markdown; charset=utf-8", err
}

func (b *Browser) screenshot(ctx context.Context, _ request) ([]byte, string, error) {
	png, err := b.call(ctx, "screenshot")
	if err != nil {
		return nil, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(png)
	return raw, "image/png", err
}

// call runs one of the extension's API functions on the command's tab, within the command's bounds.
func (b *Browser) call(ctx context.Context, function string) (string, error) {
	id := chromedp.FromContext(ctx).Target.TargetID
	worker, cancel := context.WithCancel(b.worker)
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()
	return chromedp.Run(worker, chromedp.Evaluate[string](fmt.Sprintf("%s(%q)", function, id), chromedp.EvalAwaitPromise))
}

type Request facts.Browser

func (v *Request) Describe(c connector.Context) (facts.Facts, error) {
	details := facts.Details{Browser: (*facts.Browser)(v)}
	config, _ := c.Config.(*Browser)
	action := map[string]string{"navigate": "browse", "snapshot": "browse", "text": "browse", "screenshot": "browse", "click": "submit", "type": "submit", "fill": "submit"}[v.Command]
	scope := map[string]any{"host": v.Host}
	if len(v.Secrets) > 0 {
		action, scope["secrets"] = "login", v.Secrets
	}
	// Without saved logins the browser sees only the public web.
	var observes facts.Label
	if config == nil || len(config.Slots) == 0 {
		observes.Audience = "anyone"
	}
	op := &facts.Operation{Action: action}
	return facts.Facts{Operation: op, Title: v.Command + " " + v.URL, Parameters: scope, Details: details, Context: facts.Context{Observes: observes}}, nil
}
