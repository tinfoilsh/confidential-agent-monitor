package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/gzhttp"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const Owner = "owner"

// Caller is an authenticated admin request, at the generation its client has saved.
type Caller struct {
	Name        string
	Owner       bool           // Holds the owner key.
	Claims      map[string]any // Verified by the caller's transport, for policy to read.
	Minimum     uint64
	Acknowledge func() error
	ID          string
	Key         []byte // The storage key the transport authenticated with.
}

type callerKey struct{}

func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// An error's HTTPStatus() picks the status; any other error is 400.
func JSON[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return gzhttp.GzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var err error
		var req T
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if r.Method == http.MethodPost {
			var raw []byte
			raw, err = io.ReadAll(r.Body)
			if err == nil {
				err = facts.DecodeNumbers(raw, &req)
			}
		}
		if err != nil {
			Error(w, err)
			return
		}
		value, err := fn(r, req)
		if err != nil {
			Error(w, err)
			return
		}
		response, err := json.Marshal(value)
		if err != nil {
			Error(w, err)
			return
		}
		if session, ok := CallerFrom(r.Context()); ok && session.Acknowledge != nil {
			if err := session.Acknowledge(); err != nil {
				Error(w, err)
				return
			}
		}
		// Validate only after authentication and the SSH generation acknowledgement.
		// A weak validator covers both identity and compressed representations of this JSON.
		if r.Method == http.MethodGet {
			tag := fmt.Sprintf(`W/"%x"`, sha256.Sum256(response))
			w.Header().Set("ETag", tag)
			for _, known := range strings.Split(r.Header.Get("If-None-Match"), ",") {
				known = strings.TrimSpace(known)
				if known == "*" || strings.TrimPrefix(known, "W/") == strings.TrimPrefix(tag, "W/") {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
}

func Error(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var specific interface{ HTTPStatus() int }
	if errors.As(err, &specific) {
		status = specific.HTTPStatus()
	}
	http.Error(w, err.Error(), status)
}
