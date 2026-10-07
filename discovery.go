package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

const discoveryHost = "agent.monitor"

// Discovery describes reachable connections, not the owner's configuration or credentials.
type agentConnection struct {
	Name    string `json:"name"`
	Account string `json:"account"`
	Kind    string `json:"kind"`
	Host    string `json:"host"`
	State   string `json:"state"`
	Access  access `json:"access"`
}

func (m *monitor) discoveryHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", func(w http.ResponseWriter, r *http.Request) {
		st := m.live.Load()
		p, ok := st.principals[key]
		if !ok {
			http.Error(w, "identity removed", http.StatusForbidden)
			return
		}
		connections := []agentConnection{}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			if !p.reaches(c.account) {
				continue
			}
			state := "connecting"
			select {
			case <-c.done:
				state = "stopped"
				if c.err != nil {
					state = "error"
				}
			default:
				select {
				case <-c.ready:
					state = "ready"
				default:
				}
			}
			connections = append(connections, agentConnection{
				Name: name, Account: c.account, Kind: c.protocol, Host: name + ".monitor",
				State: state, Access: p.Accounts[c.account],
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(struct {
			Connections []agentConnection `json:"connections"`
		}{connections})
	})
	return mux
}

// The SSH identity supplies authorization; the owner API is never exposed here.
func (m *monitor) forwardDiscovery(p principal, nc ssh.NewChannel, port uint32) {
	if port != 80 {
		nc.Reject(ssh.Prohibited, "agent.monitor uses HTTP on port 80 inside the SSH tunnel")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	ctx, cancel := context.WithTimeout(context.Background(), readHeaderTimeout)
	defer cancel()
	s := connector.NewStream(ctx)
	s.Conn, s.Name = channelConn{ch}, discoveryHost
	defer s.Close()
	if err := m.trackStream(p.Key, s); err != nil {
		return
	}
	in := connector.NewListener()
	defer in.Close()
	stop := context.AfterFunc(s.Context, func() { in.Close(); s.Close() })
	defer stop()
	server := &http.Server{Handler: m.discoveryHandler(p.Key), MaxHeaderBytes: 8192,
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext:       func(context.Context, net.Conn) context.Context { return s.Context }}
	server.SetKeepAlivesEnabled(false)
	defer server.Close()
	go in.Hand(s)
	if err := server.Serve(in); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("discovery HTTP: %v", err)
	}
}
