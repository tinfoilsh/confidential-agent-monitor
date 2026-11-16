package perimeter

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/monitor"
)

const (
	ownerProtocol   = "monitor-owner-v1"
	ownerRPCSession = "owner-rpc"
)

func ownerRPC(api http.Handler, generation liveGeneration) func(context.Context, ownerCall) ownerReply {
	serve := callHandler(api)
	return func(ctx context.Context, call ownerCall) ownerReply {
		if !validRPCPath(call.Path) || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && len(call.Body) != 0) {
			return ownerReply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if generation.stale(call.Generation) {
			return ownerReply{Status: http.StatusConflict, Body: []byte(errStaleGeneration.Error())}
		}
		// An admitted effect finishes even if its socket closes.
		if call.Method == http.MethodPost {
			ctx = context.WithoutCancel(ctx)
		}
		session := monitor.Caller{Name: monitor.Owner, Owner: true, Minimum: call.Generation, ID: ownerRPCSession}
		return serve(monitor.WithCaller(ctx, session), call)
	}
}

// validRPCPath accepts an origin-relative owner API path; it checks ownerPath after percent-decoding.
func validRPCPath(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.Contains(raw, "\\") &&
		u.Scheme == "" && u.Host == "" && u.User == nil && u.Opaque == "" && u.Fragment == "" &&
		path.Clean(u.Path) == u.Path && ownerPath(u.Path)
}

// ownerPath refuses the app, a nested owner session, and paths an upstream could resolve differently.
func ownerPath(p string) bool {
	return !strings.Contains(p, "..") && !strings.Contains(p, "\\") && !slices.ContainsFunc([]string{"/app", "/owner"}, func(reserved string) bool {
		return p == reserved || strings.HasPrefix(p, reserved+"/")
	})
}

var errStaleGeneration = errors.New("Perimeter state is older than the saved generation")

// liveGeneration reports the live generation, and false while the Monitor is locked.
type liveGeneration func() (uint64, bool)

// stale reports a live state older than a generation the owner has saved.
func (g liveGeneration) stale(minimum uint64) bool {
	current, unlocked := g()
	return unlocked && current < minimum
}
