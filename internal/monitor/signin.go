package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/internal/ownerauth"
)

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Path       []string        `json:"path"`
	Credential json.RawMessage `json:"credential"`
}

type finishSignInInput struct {
	Code     string  `json:"code"`
	ClientID string  `json:"client_id,omitempty"`
	Error    *string `json:"error,omitempty"`
	Cancel   bool    `json:"cancel,omitempty"`
}

type pendingSignIn struct {
	finish  func(context.Context, finishSignInInput) error
	session string
	expires time.Time
	done    <-chan struct{}
	cancel  context.CancelFunc
}

func (m *monitor) startSignIn(r *http.Request, req signInInput) (any, error) {
	previous, save, err := m.signInCredential(r.PathValue("account"), req.Path)
	if err != nil {
		return nil, err
	}
	record := previous
	if req.Credential != nil {
		record = req.Credential
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	session, _ := ownerauth.FromContext(r.Context())
	pending := &pendingSignIn{session: session.ID, expires: time.Now().Add(10 * time.Minute)}
	sign, err := credential.NewSignIn(ctx, m.live.Load().Client(), record, req.Redirect)
	if err != nil {
		return nil, err
	}
	var response any = map[string]string{"url": sign.URL}
	if sign.UserCode == "" {
		pending.finish = func(ctx context.Context, result finishSignInInput) error {
			if result.Error != nil {
				return errors.New("sign-in was not completed; try again")
			}
			secret, err := sign.Exchange(ctx, result.Code, result.ClientID)
			if err != nil {
				return err
			}
			return save(ctx, secret)
		}
	} else {
		poll, stop := context.WithDeadline(context.Background(), sign.Expires)
		done := make(chan struct{})
		var secret json.RawMessage
		var failure error
		go func() {
			defer close(done)
			defer stop()
			secret, failure = sign.WaitDevice(poll)
		}()
		pending.expires, pending.done, pending.cancel = sign.Expires, done, stop
		pending.finish = func(ctx context.Context, result finishSignInInput) error {
			if result.Error != nil {
				return errors.New("sign-in was not completed; try again")
			}
			if failure != nil {
				return failure
			}
			return save(ctx, secret)
		}
		response = map[string]any{"url": sign.URL, "state": sign.State, "user_code": sign.UserCode, "expires": sign.Expires}
	}
	m.signIns.Store(sign.State, pending)
	time.AfterFunc(time.Until(pending.expires), func() { m.signIns.CompareAndDelete(sign.State, pending) })
	return response, nil
}

func (m *monitor) finishSignIn(r *http.Request, req finishSignInInput) (any, error) {
	state := r.PathValue("state")
	value, ok := m.signIns.Load(state)
	if !ok {
		return nil, errors.New("sign-in expired or already completed; start again")
	}
	pending := value.(*pendingSignIn)
	session, _ := ownerauth.FromContext(r.Context())
	if pending.session != session.ID {
		return nil, errors.New("sign-in belongs to a different Monitor session")
	}
	if !req.Cancel && req.Error == nil && pending.done != nil && time.Now().Before(pending.expires) {
		select {
		case <-pending.done:
		default:
			return map[string]bool{"pending": true}, nil
		}
	}
	if !m.signIns.CompareAndDelete(state, pending) {
		return nil, errors.New("sign-in expired or already completed; start again")
	}
	if pending.cancel != nil {
		defer pending.cancel()
	}
	if !time.Now().Before(pending.expires) {
		return nil, errors.New("sign-in expired or already completed; start again")
	}
	if req.Cancel {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := pending.finish(ctx, req)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view(err)
}
