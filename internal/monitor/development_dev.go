//go:build monitor_dev

package monitor

import "net/http"

// Development builds retain raw custom-preset inspection for policy tooling.
// Release builds do not register this route or decode custom preset state.
func (m *monitor) registerDevelopmentOwnerRoutes(mux *http.ServeMux) {
	mux.Handle("GET /presets/{name}", ownerTx(m, func(r *http.Request, _ struct{}) (any, error) {
		return m.settings.Load().Config.Preset(r.PathValue("name"))
	}))
}
