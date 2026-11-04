//go:build !monitor_dev

package monitor

import "net/http"

func (m *monitor) registerDevelopmentOwnerRoutes(*http.ServeMux) {}
