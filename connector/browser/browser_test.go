package browser

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/tinfoilsh/monitor/connector"
)

// slowPage holds /slow long enough to pause during the load, and well short of commandTimeout.
const slowPage = 3 * time.Second

// site serves testdata/site, the pages that go run ./connector/browser/testdata/site serves by hand.
// slow reports each request to /slow when it arrives.
func site(t *testing.T) (string, chan struct{}) {
	slow := make(chan struct{}, 8)
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("testdata/site")))
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slow <- struct{}{}:
		default:
		}
		time.Sleep(slowPage)
		http.Redirect(w, r, "/index.html", http.StatusFound)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s.URL, slow
}

type harness struct {
	t     *testing.T
	b     *Browser
	agent *http.Client
	mu    sync.Mutex
	gate  func(connector.Event) error
	// stop closes first on cleanup, so a gate the test holds lets go and the connector can shut down.
	stop chan struct{}
}

// start runs a browser connection as the monitor does, with the agent reaching it over streams and the network open only to loopback.
func start(t *testing.T) *harness {
	extension, _ := filepath.Abs(cmp.Or(os.Getenv("ENGLISH_ONLY"), "../../../english-only"))
	if _, err := os.Stat(filepath.Join(extension, "manifest.json")); err != nil {
		t.Skipf("no english-only extension at %s; set ENGLISH_ONLY", extension)
	}
	h := &harness{t: t, b: &Browser{Extension: extension}, gate: func(connector.Event) error { return nil }, stop: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	in := connector.NewListener()
	ready, done := make(chan struct{}), make(chan error, 1)
	env := &connector.Env{Dialer: connector.NewDialer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})}
	go func() { done <- h.b.Run(ctx, env, in, func() { close(ready) }) }()
	t.Cleanup(func() {
		close(h.stop)
		if h.agent != nil {
			h.agent.CloseIdleConnections()
		}
		cancel()
		in.Close()
		<-done
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal(err)
	}
	h.agent = &http.Client{Timeout: time.Minute, Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		s := connector.NewStream(context.Background())
		s.Conn, s.Name = server, "browser"
		s.Gate = func(e connector.Event) error {
			h.mu.Lock()
			gate := h.gate
			h.mu.Unlock()
			return gate(e)
		}
		go in.Hand(s)
		return client, nil
	}}}
	return h
}

func (h *harness) setGate(gate func(connector.Event) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gate = gate
}

// do sends one agent command; it is safe from other goroutines.
func (h *harness) do(method, path string, body any) (int, string) {
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, "http://browser.monitor"+path, r)
	res, err := h.agent.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

func (h *harness) must(method, path string, body any) string {
	h.t.Helper()
	status, out := h.do(method, path, body)
	if status != http.StatusOK {
		h.t.Fatalf("%s %s: %d %s", method, path, status, out)
	}
	return out
}

// ref finds the ref of the first snapshot line that has text.
func ref(t *testing.T, snapshot, text string) string {
	t.Helper()
	for _, line := range strings.Split(snapshot, "\n") {
		if strings.Contains(line, text) {
			return strings.Fields(line)[0]
		}
	}
	t.Fatalf("no %q in the snapshot:\n%s", text, snapshot)
	return ""
}

func (h *harness) owner(c control) (frame, int, string) {
	raw, _ := json.Marshal(c)
	w := httptest.NewRecorder()
	h.b.ServeOwner(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	var f frame
	json.Unmarshal(w.Body.Bytes(), &f)
	return f, w.Code, w.Body.String()
}

// mustOwner aims an input at the latest frame, as the owner's view does.
func (h *harness) mustOwner(c control) frame {
	h.t.Helper()
	if c.Frame == "" && !slices.Contains([]string{"", "pause", "resume", "dialog", "tab"}, c.Action) {
		c.Frame = h.look().Frame
	}
	f, status, out := h.owner(c)
	if status != http.StatusOK {
		h.t.Fatalf("owner %s: %d %s", c.Action, status, out)
	}
	return f
}

// eval reads the active tab's page directly, as a test oracle the agent does not have.
func (h *harness) eval(js string) any {
	h.t.Helper()
	ctx, done := h.b.command(context.Background())
	defer done()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[any](js))
	if err != nil {
		h.t.Fatalf("%s: %v", js, err)
	}
	return v
}

// wait polls the owner's view until ok; a page that is committing has no frame for a moment, as the owner's view also sees.
func (h *harness) wait(what string, ok func(frame) bool) frame {
	h.t.Helper()
	var last frame
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if last = h.mustOwner(control{}); ok(last) {
			return last
		}
	}
	h.t.Fatalf("never %s; last %d tabs, url %q, error %q", what, len(last.Tabs), last.URL, last.Error)
	return frame{}
}

func (h *harness) look() frame {
	h.t.Helper()
	return h.wait("captured", func(f frame) bool { return f.Error == "" })
}

// waitURL waits until the active tab shows a page whose URL ends with suffix, among tabs open.
func (h *harness) waitURL(suffix string, tabs int) frame {
	h.t.Helper()
	return h.wait("at "+suffix, func(f frame) bool { return len(f.Tabs) == tabs && f.Error == "" && strings.HasSuffix(f.URL, suffix) })
}

// waitTabs waits until tabs are open; the active one changes only with the next command.
func (h *harness) waitTabs(tabs int) {
	h.t.Helper()
	h.wait(fmt.Sprint(tabs, " tabs"), func(f frame) bool { return len(f.Tabs) == tabs })
}

// ownerClick clicks the centre of the element, as the owner would on the screenshot.
func (h *harness) ownerClick(selector string) {
	h.t.Helper()
	r := h.eval(fmt.Sprintf(`(r => [r.x + r.width / 2, r.y + r.height / 2])(document.querySelector(%q).getBoundingClientRect())`, selector)).([]any)
	h.mustOwner(control{Action: "click", X: r[0].(float64), Y: r[1].(float64)})
}

// next receives from ch, failing rather than hanging if nothing arrives.
func next[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(time.Minute):
		t.Fatal("timed out waiting")
		panic("unreachable")
	}
}

// loading waits until the server has the request for /slow, failing at once if the request that should load it returns first.
func loading(t *testing.T, slow <-chan struct{}, returned chan int) {
	t.Helper()
	select {
	case <-slow:
	case status := <-returned:
		returned <- status
		t.Fatalf("the request for /slow returned %d before loading it", status)
	case <-time.After(time.Minute):
		t.Fatal("timed out waiting for /slow")
	}
}

func conflict(t *testing.T, status int, out, what string) {
	t.Helper()
	if status != http.StatusConflict {
		t.Fatalf("%s: %d %.300s, want 409", what, status, out)
	}
}

// The owner signs in through a password and a code while the agent waits, then the agent finishes on the same session.
func TestHandoff(t *testing.T) {
	url, _ := site(t)
	h := start(t)
	for _, path := range []string{"/pause", "/resume", "/connections/browser/browser", "/"} {
		if status, _ := h.do("POST", path, control{Action: "pause"}); status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Fatalf("the agent reached %s: %d", path, status)
		}
	}
	h.must("POST", "/navigate", request{URL: url + "/login.html"})
	stale := ref(t, h.must("GET", "/snapshot", nil), `textbox "User`)
	if _, status, out := h.owner(control{Action: "click", X: 1, Y: 1}); status != http.StatusConflict {
		t.Fatalf("owner input while the agent has control: %d %s", status, out)
	}

	if f := h.mustOwner(control{Action: "pause"}); !f.Owner || !bytes.HasPrefix(f.Screenshot, []byte{0xff, 0xd8}) {
		t.Fatalf("paused frame: owner %v, %d bytes of screenshot", f.Owner, len(f.Screenshot))
	}
	for _, path := range []string{"/snapshot", "/text", "/screenshot"} {
		status, out := h.do("GET", path, nil)
		conflict(t, status, out, "agent "+path+" while paused")
	}
	h.ownerClick("#user")
	h.mustOwner(control{Action: "type", Text: "ada"})
	h.ownerClick("#password")
	h.mustOwner(control{Action: "type", Text: "fixture"})
	h.mustOwner(control{Action: "key", Key: "Enter"})
	h.waitURL("/code.html", 1)
	h.ownerClick("#code")
	h.mustOwner(control{Action: "type", Text: "123456"})
	h.mustOwner(control{Action: "key", Key: "Enter"})
	h.waitURL("/account.html", 1)
	if f := h.mustOwner(control{Action: "resume"}); f.Owner {
		t.Fatal("resume left the owner in control")
	}

	status, out := h.do("POST", "/type", request{Ref: stale, Text: "x"})
	conflict(t, status, out, "a ref from before the handoff")
	snapshot := h.must("GET", "/snapshot", nil)
	if !strings.Contains(snapshot, `heading "Signed in as`) {
		t.Fatalf("the agent does not see the session:\n%s", snapshot)
	}
	h.must("POST", "/click", request{Ref: ref(t, snapshot, `button "Sign out"`)})
	h.waitURL("/account.html", 1)
	if signedIn := h.eval(`document.cookie.includes('session=')`); signedIn != false {
		t.Fatal("the agent's sign out did not reach the owner's session")
	}
}

// A pause takes effect during a slow load: the load ends, and agent commands queued behind it never run, even after the owner returns control.
func TestPauseDuringNavigation(t *testing.T) {
	url, slow := site(t)
	h := start(t)
	h.must("POST", "/navigate", request{URL: url + "/"})
	press := ref(t, h.must("GET", "/snapshot", nil), `button "Press"`)

	navigated := make(chan int, 1)
	go func() { status, _ := h.do("POST", "/navigate", request{URL: url + "/slow"}); navigated <- status }()
	loading(t, slow, navigated)
	queued := make(chan int, 1)
	go func() { status, _ := h.do("POST", "/click", request{Ref: press}); queued <- status }()
	time.Sleep(100 * time.Millisecond) // The click is admitted and waiting for the browser.

	began := time.Now()
	h.mustOwner(control{Action: "pause"})
	if took := time.Since(began); took > slowPage/2 {
		t.Fatalf("pause waited %v for the load", took)
	}
	if status := next(t, navigated); status != http.StatusConflict {
		t.Fatalf("interrupted navigate: %d, want 409", status)
	}
	h.mustOwner(control{Action: "resume"})
	if status := next(t, queued); status != http.StatusConflict {
		t.Fatalf("a click queued before the pause: %d, want 409", status)
	}
	if presses := h.eval(`presses`); presses != 0.0 {
		t.Fatalf("presses = %v after a refused click", presses)
	}
}

// A command waiting on the owner's approval does not run if the owner took control meanwhile, and owner input queued before a return does not run after it.
func TestPauseDuringApproval(t *testing.T) {
	url, slow := site(t)
	h := start(t)
	h.must("POST", "/navigate", request{URL: url + "/"})
	press := ref(t, h.must("GET", "/snapshot", nil), `button "Press"`)

	waiting, release := make(chan struct{}), make(chan struct{})
	h.setGate(func(e connector.Event) error {
		if e.Browser.Command == "click" {
			select {
			case waiting <- struct{}{}:
				select {
				case <-release:
				case <-h.stop:
				}
			case <-h.stop:
			}
		}
		return nil
	})
	approved := make(chan int, 1)
	go func() { status, _ := h.do("POST", "/click", request{Ref: press}); approved <- status }()
	next(t, waiting)
	h.mustOwner(control{Action: "pause"})
	h.mustOwner(control{Action: "resume"})
	close(release)
	if status := next(t, approved); status != http.StatusConflict {
		t.Fatalf("approved after a handoff: %d, want 409", status)
	}
	if presses := h.eval(`presses`); presses != 0.0 {
		t.Fatalf("presses = %v after a refused click", presses)
	}
	h.setGate(func(connector.Event) error { return nil })
	press = ref(t, h.must("GET", "/snapshot", nil), `button "Press"`)
	h.must("POST", "/click", request{Ref: press})
	if presses := h.eval(`presses`); presses != 1.0 {
		t.Fatalf("presses = %v after an approved click", presses)
	}

	h.mustOwner(control{Action: "pause"})
	loaded := make(chan int, 1)
	aim := h.look().Frame
	go func() {
		_, status, _ := h.owner(control{Action: "navigate", URL: url + "/slow", Frame: aim})
		loaded <- status
	}()
	loading(t, slow, loaded)
	queued := make(chan int, 1)
	go func() {
		_, status, _ := h.owner(control{Action: "navigate", URL: url + "/sent.html", Frame: aim})
		queued <- status
	}()
	time.Sleep(100 * time.Millisecond)
	h.mustOwner(control{Action: "resume"})
	if status := next(t, queued); status != http.StatusConflict {
		t.Fatalf("owner input queued before the return: %d, want 409", status)
	}
	next(t, loaded)
	if f := h.waitURL(url+"/", 1); f.Owner {
		t.Fatal("the owner kept control")
	}
}

// Refs name one document: a reload, a new tab at the same URL, a late redirect and a popup each need a new snapshot.
func TestStaleRefs(t *testing.T) {
	url, _ := site(t)
	h := start(t)
	h.must("POST", "/navigate", request{URL: url + "/"})
	snapshot := h.must("GET", "/snapshot", nil)

	h.must("POST", "/click", request{Ref: ref(t, snapshot, `button "Reload"`)})
	h.waitURL(url+"/", 1)
	status, out := h.do("POST", "/click", request{Ref: ref(t, snapshot, `button "Press"`)})
	conflict(t, status, out, "a ref from before a reload")

	snapshot = h.must("GET", "/snapshot", nil)
	h.must("POST", "/click", request{Ref: ref(t, snapshot, `link "Open home in a new tab"`)})
	h.waitTabs(2)
	status, out = h.do("POST", "/click", request{Ref: ref(t, snapshot, `button "Press"`)})
	conflict(t, status, out, "a ref from the other tab at the same URL")
	h.waitURL(url+"/", 2)
	h.must("POST", "/click", request{Ref: ref(t, h.must("GET", "/snapshot", nil), `button "Press"`)})
	if presses := h.eval(`presses`); presses != 1.0 {
		t.Fatalf("presses in the new tab = %v", presses)
	}
	f := h.mustOwner(control{Action: "pause"})
	first := f.Tabs[slices.IndexFunc(f.Tabs, func(t tab) bool { return !t.Active })]
	h.mustOwner(control{Action: "tab", Tab: string(first.ID)})
	h.mustOwner(control{Action: "resume"})
	if presses := h.eval(`presses`); presses != 0.0 {
		t.Fatalf("presses in the first tab = %v", presses)
	}

	snapshot = h.must("GET", "/snapshot", nil)
	h.must("POST", "/click", request{Ref: ref(t, snapshot, `button "Go to the account page later"`)})
	h.waitURL("/account.html", 2)
	status, out = h.do("POST", "/click", request{Ref: ref(t, snapshot, `button "Press"`)})
	conflict(t, status, out, "a ref from before a late redirect")

	h.must("POST", "/navigate", request{URL: url + "/"})
	snapshot = h.must("GET", "/snapshot", nil)
	h.must("POST", "/click", request{Ref: ref(t, snapshot, `button "Open a popup"`)})
	h.waitTabs(3)
	status, out = h.do("POST", "/click", request{Ref: ref(t, snapshot, `button "Press"`)})
	conflict(t, status, out, "an opener's ref while its popup is active")
	h.waitURL("/popup.html", 3)
	h.must("POST", "/click", request{Ref: ref(t, h.must("GET", "/snapshot", nil), `button "Done"`)})
	h.waitTabs(2)
	h.must("GET", "/snapshot", nil)
	if done := h.eval(`helped.textContent`); !regexp.MustCompile(`popup is done`).MatchString(done.(string)) {
		t.Fatalf("the opener did not keep its state: %q", done)
	}
}

// Each connection has its own profile, so one connection's sign-in is not another's.
func TestSessionsIsolated(t *testing.T) {
	url, _ := site(t)
	a, b := start(t), start(t)
	a.must("POST", "/navigate", request{URL: url + "/"})
	b.must("POST", "/navigate", request{URL: url + "/"})
	a.eval(`document.cookie = 'session=ada; path=/'; localStorage.note = 'kept'`)
	if got := b.eval(`document.cookie + '|' + Object.keys(localStorage).join()`); got != "|" {
		t.Fatalf("the other connection sees %q", got)
	}
	b.must("POST", "/navigate", request{URL: url + "/account.html"})
	if got := b.eval(`state.textContent`); got != "Not signed in" {
		t.Fatalf("the other connection's account page: %q", got)
	}
	if got := a.eval(`document.cookie + '|' + localStorage.note`); got != "session=ada|kept" {
		t.Fatalf("the first connection lost its session: %q", got)
	}
}

// Owner input acts only on the frame it was aimed at: not after the page changes, nor in a later takeover.
// A dialog that stops capture leaves control accurate and can be closed.
func TestOwnerFrames(t *testing.T) {
	url, _ := site(t)
	h := start(t)
	h.must("POST", "/navigate", request{URL: url + "/"})
	h.mustOwner(control{Action: "pause"})
	before := h.look()
	h.ownerClick("#note")
	h.mustOwner(control{Action: "type", Text: "kept", Frame: before.Frame})
	h.ownerClick(`button[onclick="location.reload()"]`)
	h.wait("reloaded", func(f frame) bool { return f.Error == "" && f.Frame != before.Frame })
	_, status, out := h.owner(control{Action: "type", Text: "lost", Frame: before.Frame})
	conflict(t, status, out, "owner input aimed at the page before a reload")

	again := h.look()
	h.mustOwner(control{Action: "resume"})
	h.mustOwner(control{Action: "pause"})
	_, status, out = h.owner(control{Action: "type", Text: "lost", Frame: again.Frame})
	conflict(t, status, out, "owner input from an earlier takeover")
	if note := h.eval(`note.value`); note != "" {
		t.Fatalf("stale owner input reached the page: %q", note)
	}

	// Chrome holds input that opens a dialog until the dialog closes; the click must come back so the owner can close it.
	at := h.eval(`(r => [r.x + r.width / 2, r.y + r.height / 2])(document.querySelector('button[onclick^="alert("]').getBoundingClientRect())`).([]any)
	began := time.Now()
	f, status, out := h.owner(control{Action: "click", Frame: h.look().Frame, X: at[0].(float64), Y: at[1].(float64)})
	if status != http.StatusOK || time.Since(began) > captureTimeout {
		t.Fatalf("a click that opens a dialog: %d %.200s after %v", status, out, time.Since(began))
	}
	if !f.Owner || f.Error == "" || f.Frame != "" {
		t.Fatalf("view with a dialog open: owner %v, error %q, frame %q", f.Owner, f.Error, f.Frame)
	}
	h.mustOwner(control{Action: "dialog"})
	if f := h.look(); !f.Owner || len(f.Screenshot) == 0 {
		t.Fatal("no view after closing the dialog")
	}
	h.ownerClick(`button[onclick^="count"]`)
	if presses := h.eval(`presses`); presses != 1.0 {
		t.Fatalf("presses after the dialog = %v", presses)
	}
	h.mustOwner(control{Action: "resume"})
	if f := h.mustOwner(control{}); f.Owner {
		t.Fatal("resume left the owner in control")
	}
}

// The owner opens a popup from the page, picks it, finishes it, and the opener is active again with its state; the agent then carries on there.
func TestOwnerPopup(t *testing.T) {
	url, _ := site(t)
	h := start(t)
	h.must("POST", "/navigate", request{URL: url + "/"})
	h.mustOwner(control{Action: "pause"})
	h.ownerClick(`button[onclick^="window.open("]`)
	f := h.wait("listing the popup", func(f frame) bool { return len(f.Tabs) == 2 && f.Error == "" })
	if !strings.HasSuffix(f.URL, url+"/") {
		t.Fatalf("a popup took the owner's view without being picked: %s", f.URL)
	}
	// The owner keeps working in the opener with the frame they see; the input that first finds the popup must not move to it.
	press := h.eval(`(r => [r.x + r.width / 2, r.y + r.height / 2])(document.querySelector('button[onclick^="count"]').getBoundingClientRect())`).([]any)
	if after := h.mustOwner(control{Action: "click", Frame: f.Frame, X: press[0].(float64), Y: press[1].(float64)}); after.Frame != f.Frame {
		t.Fatalf("owner input moved the view from %s to %s", f.URL, after.URL)
	}
	if presses := h.eval(`presses`); presses != 1.0 {
		t.Fatalf("presses in the opener = %v", presses)
	}
	popup := f.Tabs[slices.IndexFunc(f.Tabs, func(t tab) bool { return !t.Active })]
	h.mustOwner(control{Action: "tab", Tab: string(popup.ID)})
	h.waitURL("/popup.html", 2)
	h.ownerClick("button")
	h.waitURL(url+"/", 1)
	h.mustOwner(control{Action: "resume"})
	snapshot := h.must("GET", "/snapshot", nil)
	if done := h.eval(`helped.textContent`); done != "The popup is done" {
		t.Fatalf("the opener did not keep its state: %q", done)
	}
	h.must("POST", "/click", request{Ref: ref(t, snapshot, `button "Press"`)})
	if presses := h.eval(`presses`); presses != 2.0 {
		t.Fatalf("presses = %v", presses)
	}
}
