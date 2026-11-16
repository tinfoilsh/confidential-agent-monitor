// Package httpjson decodes bounded JSON request bodies, keeping numbers exactly as written.
package httpjson

import (
	"io"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

// Decode reads at most limit bytes of r's body into out, refusing unknown members.
func Decode(w http.ResponseWriter, r *http.Request, limit int64, out any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	return facts.DecodeNumbers(raw, out)
}
