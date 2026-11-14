package owner

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/monitor"
)

// Bearer serves API as the owner to calls whose bearer token is the base64 storage key, for
// local development. Other calls reach API without a caller.
type Bearer struct {
	API     http.Handler
	IsOwner func(key []byte) bool
}

func (b *Bearer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key, err := base64.StdEncoding.Strict().DecodeString(token); ok && err == nil && b.IsOwner(key) {
		r = r.WithContext(monitor.WithCaller(r.Context(), monitor.Caller{Name: monitor.Owner, Owner: true, Key: key}))
	}
	b.API.ServeHTTP(w, r)
}
