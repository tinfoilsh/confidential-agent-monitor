package browser

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/accessibility"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/elazarl/goproxy"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
)

const (
	loopback     = "127.0.0.1:0"
	extensionURL = "chrome-extension://"
	workerType   = "service_worker"
	startPage    = "about:blank"
	refPrefix    = "e"
	inputNode    = "INPUT"
)

// Browser drives one Chromium tab with the english-only extension loaded, so the agent sees only censored pages.
// The agent fills a form slot's placeholder; the monitor types the value into a field on the slot's origin.
type Browser struct {
	web.Credentials
	Extension string `json:"-"`
	mu        sync.Mutex
	tab       context.Context
	worker    context.Context
}

type request struct {
	URL  string `json:"url"`
	Ref  string `json:"ref"`
	Text string `json:"text"`
	// connection names the placeholders; slot is the form slot a fill's placeholder names.
	connection string
	slot       *web.Slot
}

func (b *Browser) UnmarshalJSON(raw []byte) error {
	type plain Browser
	if err := connector.Decode(raw, (*plain)(b)); err != nil {
		return err
	}
	return b.Validate(true)
}

func (b *Browser) Run(ctx context.Context, e *connector.Env, in *connector.Listener, ready func()) error {
	proxy, err := b.proxy(e)
	if err != nil {
		return err
	}
	defer proxy.Close()
	alloc, cancel := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:],
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
	b.tab = tab
	mux := http.NewServeMux()
	mux.HandleFunc("POST /navigate", b.handle("navigate", b.navigate))
	mux.HandleFunc("GET /snapshot", b.handle("snapshot", b.snapshot))
	mux.HandleFunc("GET /text", b.handle("text", b.text))
	mux.HandleFunc("GET /screenshot", b.handle("screenshot", b.screenshot))
	mux.HandleFunc("POST /click", b.handle("click", b.click))
	mux.HandleFunc("POST /type", b.handle("type", b.typeText))
	mux.HandleFunc("POST /fill", b.handle("fill", b.fill))
	return connector.ServeHTTP(ctx, in, ready, mux)
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
func (b *Browser) handle(command string, do func(context.Context, request) ([]byte, string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		page := req.URL
		if command != "navigate" {
			var err error
			if page, err = chromedp.Run(b.tab, chromedp.Location()); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		u, err := url.Parse(page)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			http.Error(w, fmt.Sprintf("%q is not an http or https page", page), http.StatusForbidden)
			return
		}
		stream := connector.RequestStream(r)
		req.connection = stream.Name
		if req.slot, err = b.secret(command, req); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		layer := &connector.BrowserLayer{Command: command, URL: u.String(), Host: strings.ToLower(u.Hostname()), Text: req.Text}
		if req.slot != nil {
			layer.Secrets = []string{req.slot.Value}
		}
		if err := stream.Gate(connector.Event{Browser: layer}); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		body, kind, err := do(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", kind)
		w.Write(body)
	}
}

// secret finds the form slot a fill's placeholder names. The field's own frame must hold the slot's origin and its input type must suit the value;
// a placeholder anywhere else is refused.
func (b *Browser) secret(command string, req request) (*web.Slot, error) {
	if command != "fill" {
		for _, text := range []string{req.URL, req.Text} {
			if _, err := b.Form(req.connection, "", text); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	id, err := backend(req.Ref)
	if err != nil {
		return nil, err
	}
	origin, err := b.frameOrigin(id)
	if err != nil {
		return nil, err
	}
	slot, err := b.Form(req.connection, origin, req.Text)
	if slot == nil || err != nil {
		return nil, err
	}
	node, err := chromedp.Call(b.tab, dom.DescribeNode, dom.DescribeNodeParams{BackendNodeID: id})
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
func (b *Browser) frameOrigin(id cdp.BackendNodeID) (string, error) {
	tree, err := chromedp.Call(b.tab, accessibility.GetPartialAXTree, accessibility.GetPartialAXTreeParams{BackendNodeID: id})
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
	frames, err := chromedp.Call(b.tab, page.GetFrameTree, cdp.Empty{})
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

func backend(ref string) (cdp.BackendNodeID, error) {
	id, err := strconv.ParseInt(strings.TrimPrefix(ref, refPrefix), 10, 64)
	if err != nil || !strings.HasPrefix(ref, refPrefix) {
		return 0, fmt.Errorf("%q is not a ref from the snapshot", ref)
	}
	return cdp.BackendNodeID(id), nil
}

func (b *Browser) navigate(_ context.Context, req request) ([]byte, string, error) {
	_, err := chromedp.Run(b.tab, chromedp.Navigate(req.URL))
	return nil, "", err
}

// click presses the mouse at the centre of the node's first box, as a person would.
func (b *Browser) click(_ context.Context, req request) ([]byte, string, error) {
	id, err := backend(req.Ref)
	if err != nil {
		return nil, "", err
	}
	if _, err := chromedp.Call(b.tab, dom.ScrollIntoViewIfNeeded, dom.ScrollIntoViewIfNeededParams{BackendNodeID: id}); err != nil {
		return nil, "", err
	}
	quads, err := chromedp.Call(b.tab, dom.GetContentQuads, dom.GetContentQuadsParams{BackendNodeID: id})
	if err != nil || len(quads.Quads) == 0 {
		return nil, "", fmt.Errorf("%s is not visible", req.Ref)
	}
	q := quads.Quads[0]
	_, err = chromedp.Run(b.tab, chromedp.MouseClickXY((q[0]+q[2]+q[4]+q[6])/4, (q[1]+q[3]+q[5]+q[7])/4))
	return nil, "", err
}

// fill replaces the field's text, with the slot's value in place of its placeholder.
func (b *Browser) fill(ctx context.Context, req request) ([]byte, string, error) {
	id, err := backend(req.Ref)
	if err != nil {
		return nil, "", err
	}
	text := req.Text
	if req.slot != nil {
		// The page may have changed while the owner decided.
		if slot, err := b.secret("fill", req); slot != req.slot {
			return nil, "", cmp.Or(err, errors.New("the field no longer takes this credential"))
		}
		if text, err = b.Values[req.slot.Value].Value(ctx); err != nil {
			return nil, "", fmt.Errorf("credential %s is unavailable", req.slot.Value)
		}
	}
	if _, err := chromedp.Call(b.tab, dom.Focus, dom.FocusParams{BackendNodeID: id}); err != nil {
		return nil, "", err
	}
	node, err := chromedp.Call(b.tab, dom.ResolveNode, dom.ResolveNodeParams{BackendNodeID: id})
	if err != nil {
		return nil, "", err
	}
	if _, err := chromedp.Run(b.tab, chromedp.CallFunctionOn[any]("function() { this.select?.() }", func(p *runtime.CallFunctionOnParams) {
		p.ObjectID = node.Object.ObjectID
	})); err != nil {
		return nil, "", err
	}
	_, err = chromedp.Call(b.tab, input.InsertText, input.InsertTextParams{Text: text})
	return nil, "", err
}

func (b *Browser) typeText(_ context.Context, req request) ([]byte, string, error) {
	_, err := chromedp.Run(b.tab, chromedp.KeyEvent(req.Text))
	return nil, "", err
}

func (b *Browser) snapshot(context.Context, request) ([]byte, string, error) {
	lines, err := b.call("snapshot")
	return []byte(lines), "text/plain; charset=utf-8", err
}

func (b *Browser) text(context.Context, request) ([]byte, string, error) {
	md, err := b.call("text")
	return []byte(md), "text/markdown; charset=utf-8", err
}

func (b *Browser) screenshot(context.Context, request) ([]byte, string, error) {
	png, err := b.call("screenshot")
	if err != nil {
		return nil, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(png)
	return raw, "image/png", err
}

// call runs one of the extension's API functions on the tab.
func (b *Browser) call(function string) (string, error) {
	id := chromedp.FromContext(b.tab).Target.TargetID
	return chromedp.Run(b.worker, chromedp.Evaluate[string](fmt.Sprintf("%s(%q)", function, id), chromedp.EvalAwaitPromise))
}
