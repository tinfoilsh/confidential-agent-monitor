//go:build !monitor_dev

package main

import "github.com/tinfoilsh/monitor/connector"

func registerDevelopmentConnectors(map[string]connector.Kind, bool, bool) {}
