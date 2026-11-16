package core_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

func pickFirst(_ string, _ uint32, candidates []core.Candidate) (string, bool, bool) {
	if len(candidates) == 0 {
		return "", false, false
	}
	return candidates[0].Name, true, true
}
func permitWatch(context.Context, func()) (core.Gate, bool) {
	return func(context.Context, facts.Event) error { return nil }, true
}

func TestApplicationSelectsRouteAndPrincipal(t *testing.T) {
	principal := facts.Principal{Key: "fixed-key", Name: "alice"}
	var called atomic.Int32
	table := core.New(
		func(_ context.Context, p facts.Principal, name string) bool {
			return p.Same(principal) && name == "selected"
		},
		func(_ context.Context, p facts.Principal, request core.Request) (core.Watch, error) {
			if !p.Same(principal) || request.Connection != "selected" || !request.Valid() {
				t.Error("application admission lost principal or setup")
			}
			return permitWatch, nil
		}, pickFirst, time.Second)
	defer table.Close()
	for _, name := range []string{"inaccessible", "selected"} {
		table.Stage(name, func(string, uint32) int { return -1 }, false, func(context.Context) (core.Connector, error) {
			return core.Connector{Serve: func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate func(context.Context, facts.Event) error) {
				defer conn.Close()
				if name != "selected" || host != "" || port != 4321 {
					t.Errorf("selected stream = %s/%s/%d", name, host, port)
				}
				called.Add(1)
			}, Close: func() error { return nil }}, nil
		})
	}
	table.Start()
	server, client := net.Pipe()
	defer client.Close()
	if err := table.Open(t.Context(), principal, "arbitrary.application.name", 4321, func() (net.Conn, error) { return server, nil }); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("served %d streams", called.Load())
	}
}

func TestRestageInvalidatesWaitingAdmission(t *testing.T) {
	entered := make(chan func() bool, 1)
	release := make(chan struct{})
	var served atomic.Int32
	table := core.New(func(context.Context, facts.Principal, string) bool { return true }, func(_ context.Context, _ facts.Principal, r core.Request) (core.Watch, error) {
		entered <- r.Valid
		<-release
		if !r.Valid() {
			return nil, errors.New("setup replaced")
		}
		return permitWatch, nil
	}, pickFirst, time.Second)
	defer table.Close()
	open := func(context.Context) (core.Connector, error) {
		return core.Connector{Serve: func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
			served.Add(1)
		}, Close: func() error { return nil }}, nil
	}
	table.Stage("service", nil, false, open)
	table.Start()
	done := make(chan error, 1)
	go func() {
		done <- table.Open(t.Context(), facts.Principal{}, "target", 1, func() (net.Conn, error) {
			t.Error("replaced admission accepted")
			return nil, errors.New("unexpected accept")
		})
	}()
	var valid func() bool
	select {
	case valid = <-entered:
	case <-time.After(time.Second):
		t.Fatal("admission did not start")
	}
	if !valid() {
		t.Fatal("ready setup invalid")
	}
	table.Stage("service", nil, false, open)
	if valid() {
		t.Error("restage left old setup authority valid")
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Error("replaced admission succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("admission stuck")
	}
	table.Start()
	if served.Load() != 0 {
		t.Fatal("replaced admission forwarded input")
	}
}

func TestRemovalJoinsStreamsBeforeClosingHandler(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	finish := make(chan struct{})
	var release sync.Once
	closed := make(chan struct{})
	table := core.New(func(context.Context, facts.Principal, string) bool { return true }, func(context.Context, facts.Principal, core.Request) (core.Watch, error) { return permitWatch, nil }, pickFirst, time.Second)
	defer table.Close()
	defer release.Do(func() { close(finish) })
	table.Stage("service", nil, false, func(context.Context) (core.Connector, error) {
		return core.Connector{Serve: func(ctx context.Context, conn net.Conn, _ string, _ string, _ uint32, _ func(context.Context, facts.Event) error) {
			defer conn.Close()
			close(started)
			<-ctx.Done()
			close(canceled)
			<-finish
		}, Close: func() error { close(closed); return nil }}, nil
	})
	table.Start()
	server, client := net.Pipe()
	defer client.Close()
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- table.Open(t.Context(), facts.Principal{}, "target", 1, func() (net.Conn, error) { return server, nil })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stream did not start")
	}
	table.Remove("service")
	retired := make(chan struct{})
	go func() { table.Start(); close(retired) }()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("removal did not cancel stream")
	}
	select {
	case <-closed:
		t.Fatal("handler closed before its stream returned")
	default:
	}
	release.Do(func() { close(finish) })
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("retirement did not join")
	}
	select {
	case <-closed:
	default:
		t.Error("retired handler not closed")
	}
	if err := <-streamDone; err != nil {
		t.Fatal(err)
	}
}

func TestOnlyCurrentStagedSetupOpens(t *testing.T) {
	var opened, closed atomic.Int32
	table := core.New(func(context.Context, facts.Principal, string) bool { return true },
		func(context.Context, facts.Principal, core.Request) (core.Watch, error) { return permitWatch, nil }, pickFirst, time.Second)
	defer table.Close()
	open := func(context.Context) (core.Connector, error) {
		opened.Add(1)
		return core.Connector{
			Serve: func(context.Context, net.Conn, string, string, uint32, core.Gate) {},
			Close: func() error { closed.Add(1); return nil },
		}, nil
	}
	table.Stage("removed", nil, false, open)
	table.Remove("removed")
	table.Stage("replaced", nil, false, open)
	table.Stage("replaced", nil, false, open)
	table.Start()
	if opened.Load() != 1 {
		t.Errorf("opened %d setups; only the current replacement may open", opened.Load())
	}
	table.Remove("replaced")
	// Shutdown must also drain pending retirement without another Start.
	table.Close()
	if closed.Load() != opened.Load() {
		t.Errorf("closed %d of %d opened setups", closed.Load(), opened.Load())
	}
}

func TestMissingServeCannotBecomeReady(t *testing.T) {
	table := core.New(func(context.Context, facts.Principal, string) bool { return true },
		func(context.Context, facts.Principal, core.Request) (core.Watch, error) { return permitWatch, nil }, pickFirst, time.Second)
	defer table.Close()
	table.Stage("invalid", nil, false, func(context.Context) (core.Connector, error) { return core.Connector{}, nil })
	table.Start()
	if status := table.Connections()["invalid"]; status.State == core.Ready || status.Error == "" {
		t.Fatalf("incomplete factory result became available: %+v", status)
	}
}
