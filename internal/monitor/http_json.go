package monitor

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/ownerauth"
	"github.com/tinfoilsh/monitor/internal/sandbox"
	"github.com/tinfoilsh/monitor/internal/sandboxroute"
	"github.com/tinfoilsh/monitor/internal/store"
)

func jsonHandler[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			responseError(w, err)
			return
		}
		value, err := fn(r, req)
		if err != nil {
			responseError(w, err)
			return
		}
		if view, ok := value.(ownerView); ok && r.URL.Query().Get("catalog") == view.CatalogID {
			view.Presets = nil
			value = view
		}
		response, err := json.Marshal(value)
		if err != nil {
			responseError(w, err)
			return
		}
		if session, ok := ownerauth.FromContext(r.Context()); ok {
			if err := session.Acknowledge(); err != nil {
				responseError(w, err)
				return
			}
		}
		// Validate only after authentication and the SSH generation acknowledgement.
		// A weak validator covers both identity and gzip representations of this JSON.
		w.Header().Add("Vary", "Accept-Encoding")
		// The legacy full-history export can be hundreds of MB; the UI validates
		// its compact summaries instead of hashing all request bodies every poll.
		if r.Method == http.MethodGet && !(r.URL.Path == "/requests" && !r.URL.Query().Has("summary")) {
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
		if len(response) >= 1024 && acceptsGzip(r.Header.Get("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			defer compressed.Close()
			compressed.Write(response)
			return
		}
		w.Write(response)
	}
}

func acceptsGzip(accept string) bool {
	for _, coding := range strings.Split(accept, ",") {
		parts := strings.Split(coding, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			if key, value, ok := strings.Cut(strings.TrimSpace(parameter), "="); ok && strings.EqualFold(key, "q") {
				var err error
				quality, err = strconv.ParseFloat(value, 64)
				if err != nil {
					return false
				}
			}
		}
		return quality > 0 && quality <= 1
	}
	return false
}

func responseError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errNoAgent), errors.Is(err, errSandboxSSHDisabled):
		status = http.StatusForbidden
	case errors.Is(err, store.ErrOwner):
		status = http.StatusUnauthorized
	case errors.Is(err, errLocked):
		status = http.StatusLocked
	case errors.Is(err, store.ErrMissingState):
		status = http.StatusPreconditionRequired
	case errors.Is(err, errPolicyConflict):
		status = http.StatusConflict
	case errors.Is(err, sandboxroute.ErrUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, errRecordGone), errors.Is(err, sandbox.ErrShellGone):
		status = http.StatusNotFound
	}
	http.Error(w, err.Error(), status)
}
