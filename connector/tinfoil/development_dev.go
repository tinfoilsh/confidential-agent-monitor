//go:build monitor_dev

package tinfoil

import "net/http"

func registerDevelopmentControl(mux *http.ServeMux, state *httpState) {
	mux.HandleFunc("POST /review", state.review)
}
