//go:build monitor_dev

package main

import (
	"flag"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/browser"
)

var extension = flag.String("extension", "", "the english-only extension directory; development browser connections need it")

func registerDevelopmentConnectors(kinds map[string]connector.Kind, serveWorker, production bool) {
	if !production && (*extension != "" || serveWorker) {
		kinds["browser"] = browser.Kind(*extension, serveWorker)
	}
}
