//go:build monitor_dev

package browser

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
	"github.com/tinfoilsh/monitor/facts"
)

const (
	screenshotQuality = 70
	// A page with a dialog open draws nothing; the owner then sees the failure and can close the dialog.
	captureTimeout = 5 * time.Second
)

var (
	errAgent    = errors.New("pause the agent before using the browser")
	errReturned = errors.New("control passed since this action was sent")
	errStale    = errors.New("the page changed since the view this action was aimed at; look again")
)

// control is one owner action, aimed at the frame it names; x and y are viewport pixels of that frame's screenshot.
type control struct {
	Action string  `json:"action"`
	Frame  string  `json:"frame"`
	URL    string  `json:"url"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	DY     float64 `json:"dy"`
	Text   string  `json:"text"`
	Key    string  `json:"key"`
	Tab    string  `json:"tab"`
	Accept bool    `json:"accept"`
}

// wheel is Input.dispatchMouseEvent for a mouseWheel, which Chrome rejects without both deltas; cdproto omits a zero delta.
type wheel struct {
	Type   input.DispatchMouseEventType `json:"type"`
	X      float64                      `json:"x"`
	Y      float64                      `json:"y"`
	DeltaX float64                      `json:"deltaX"`
	DeltaY float64                      `json:"deltaY"`
}

var dispatchWheel = cdp.Command[wheel, cdp.Empty]{Method: input.CommandDispatchMouseEvent}

// frame is what the owner sees. Owner is always accurate; the capture of the active tab may fail, and Error then says why.
type frame struct {
	Owner      bool   `json:"owner"`
	Tabs       []tab  `json:"tabs"`
	Frame      string `json:"frame,omitempty"`
	URL        string `json:"url,omitempty"`
	Screenshot []byte `json:"screenshot,omitempty"`
	Error      string `json:"error,omitempty"`
}

type tab struct {
	ID     target.ID `json:"id"`
	URL    string    `json:"url"`
	Title  string    `json:"title"`
	Active bool      `json:"active"`
}

// serveOwner serves the owner's live view and controls; the agent's listener does not route here.
// The monitor serves it behind the owner's secret.
func (b *session) serveOwner(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	epoch := b.epoch
	b.mu.Unlock()
	var c control
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			err = facts.DecodeNumbers(raw, &c)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	var err error
	switch c.Action {
	case "":
	case "pause":
		b.pause(r)
	case "resume":
		b.mu.Lock()
		if b.held {
			b.held, b.epoch = false, b.epoch+1
		}
		b.mu.Unlock()
	default:
		err = b.act(r, epoch, c)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errAgent) || errors.Is(err, errReturned) || errors.Is(err, errStale) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b.view(r))
}

func (b *session) control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /browser", b.serveOwner)
	mux.HandleFunc("POST /browser", b.serveOwner)
	return mux
}

// pause takes control at once: it ends the agent's command in progress and returns when that command has let go of the browser.
// A page load the agent started stops with it.
func (b *session) pause(r *http.Request) {
	b.mu.Lock()
	running := b.stop != nil
	if !b.held {
		b.held, b.epoch = true, b.epoch+1
		if running {
			b.stop()
		}
	}
	b.mu.Unlock()
	b.op.Lock()
	defer b.op.Unlock()
	if running {
		ctx, done := b.command(r.Context())
		defer done()
		chromedp.Run(ctx, chromedp.Stop())
	}
}

// act runs one input while the owner holds the browser, in the turn it arrived in and on the frame it was aimed at.
func (b *session) act(r *http.Request, epoch int, c control) error {
	b.op.Lock()
	defer b.op.Unlock()
	b.mu.Lock()
	held, current := b.held, b.epoch == epoch
	b.mu.Unlock()
	switch {
	case !held:
		return errAgent
	case !current:
		return errReturned
	}
	if err := b.follow(r.Context(), false); err != nil {
		return err
	}
	ctx, done := b.command(r.Context())
	defer done()
	// Picking a tab names it, and a dialog blocks the page, so neither waits to look at the page.
	switch c.Action {
	case "dialog":
		_, err := chromedp.Call(ctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: c.Accept})
		return err
	case "tab":
		b.mu.Lock()
		_, open := b.tabs[target.ID(c.Tab)]
		b.use(target.ID(c.Tab))
		b.mu.Unlock()
		if !open {
			return fmt.Errorf("no tab %s", c.Tab)
		}
		return b.follow(r.Context(), false)
	}
	if _, doc, err := b.document(ctx, epoch); err != nil {
		return err
	} else if doc.token() != c.Frame {
		return errStale
	}
	var err error
	switch c.Action {
	case "navigate":
		if u, perr := url.Parse(c.URL); perr != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("%q is not an http or https page", c.URL)
		}
		_, err = chromedp.Run(ctx, chromedp.Navigate(c.URL))
	case "back":
		_, err = chromedp.Run(ctx, chromedp.NavigateBack())
	case "click":
		_, err = chromedp.Run(ctx, chromedp.MouseClickXY(c.X, c.Y))
	case "scroll":
		_, err = chromedp.Call(ctx, dispatchWheel, wheel{Type: input.DispatchMouseEventTypeMouseWheel, X: c.X, Y: c.Y, DeltaY: c.DY})
	case "type":
		_, err = chromedp.Run(ctx, chromedp.KeyEvent(c.Text))
	case "key":
		err = fmt.Errorf("unknown key %q", c.Key)
		for code, k := range kb.Keys {
			if k.Key == c.Key {
				_, err = chromedp.Run(ctx, chromedp.KeyEvent(string(code)))
				break
			}
		}
	default:
		err = fmt.Errorf("unknown action %q", c.Action)
	}
	if delivered(ctx, err) {
		return nil
	}
	return err
}

// view looks at the active tab without waiting for a command or changing which tab is active. Owner is read last,
// so it is accurate even when the capture fails.
func (b *session) view(r *http.Request) frame {
	f, err := b.capture(r)
	if err != nil {
		f = frame{Tabs: f.Tabs, Error: err.Error()}
	}
	b.mu.Lock()
	f.Owner = b.held
	b.mu.Unlock()
	return f
}

// capture takes the screenshot, URL and frame token of one document, in one epoch: if either changes meanwhile, it fails.
func (b *session) capture(r *http.Request) (frame, error) {
	var f frame
	ctx, cancel := context.WithTimeout(b.root, captureTimeout)
	defer cancel()
	defer context.AfterFunc(r.Context(), cancel)()
	pages, err := b.pages(ctx)
	if err != nil {
		return f, err
	}
	// The tab follow would keep: the most recently used one still open.
	b.mu.Lock()
	var active target.ID
	for _, id := range slices.Backward(b.order) {
		if slices.ContainsFunc(pages, func(t *target.Info) bool { return t.TargetID == id }) {
			active = id
			break
		}
	}
	selected, epoch := b.tabs[active], b.epoch
	var tabCtx context.Context
	var dialog bool
	if selected != nil {
		tabCtx, dialog = selected.context, selected.dialog
	}
	b.mu.Unlock()
	for _, t := range pages {
		f.Tabs = append(f.Tabs, tab{t.TargetID, t.URL, t.Title, t.TargetID == active})
	}
	switch {
	case tabCtx == nil:
		return f, errors.New("the browser has no open tab")
	case dialog:
		return f, errDialog
	}
	tabCtx, cancel = context.WithTimeout(tabCtx, captureTimeout)
	defer cancel()
	defer context.AfterFunc(r.Context(), cancel)()
	url, doc, err := b.document(tabCtx, epoch)
	if err != nil {
		return f, err
	}
	quality := int64(screenshotQuality)
	shot, err := chromedp.Call(tabCtx, page.CaptureScreenshot, page.CaptureScreenshotParams{Format: page.CaptureScreenshotFormatJpeg, Quality: &quality})
	if err != nil {
		return f, err
	}
	_, after, err := b.document(tabCtx, epoch)
	b.mu.Lock()
	passed := b.epoch != epoch
	b.mu.Unlock()
	if err != nil || after != doc || passed {
		return f, cmp.Or(err, errors.New("the page or control changed during the capture"))
	}
	f.URL, f.Frame, f.Screenshot = url, doc.token(), shot.Data
	return f, nil
}
