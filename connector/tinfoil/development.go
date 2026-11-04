//go:build !monitor_dev

package tinfoil

import "net/http"

func registerDevelopmentControl(*http.ServeMux, *httpState) {}
