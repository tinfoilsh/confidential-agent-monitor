package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// The standalone script and the server binary share one client implementation.
//
//go:embed client/monitor
var clientScript string

func clientCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "run", "shell", "mcp", "connections", "browser", "--profile", "--client-config", "--ssh-host", "--ssh-config", "--timeout", "--help", "-h":
		return true
	}
	for _, option := range []string{"--profile=", "--client-config=", "--ssh-host=", "--ssh-config=", "--timeout="} {
		if len(args[0]) >= len(option) && args[0][:len(option)] == option {
			return true
		}
	}
	return false
}

func execClient(args []string) error {
	python, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("the Monitor client requires Python 3.11 or newer: %w", err)
	}
	return syscall.Exec(python, append([]string{python, "-c", clientScript}, args...), os.Environ())
}
