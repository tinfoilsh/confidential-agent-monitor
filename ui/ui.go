package ui

import (
	"embed"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

//go:generate bun install --frozen-lockfile
//go:generate bun run build

//go:embed dist
var dist embed.FS

var Files, _ = fs.Sub(dist, "dist")

func DevProxy(address string) (http.Handler, error) {
	target, err := url.Parse(address)
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil ||
		(target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.Fragment != "" ||
		(target.Hostname() != "localhost" && !net.ParseIP(target.Hostname()).IsLoopback()) {
		return nil, errors.New("-ui-dev-url must be a loopback HTTP origin, such as http://127.0.0.1:5173")
	}
	target.Path = ""
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "UI development server unavailable; start it with bun dev/run.ts", http.StatusBadGateway)
	}
	return proxy, nil
}
