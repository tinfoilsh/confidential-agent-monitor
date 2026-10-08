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
	"github.com/tinfoilsh/monitor/connector/web"
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

// Client setup contains public routing and placeholder data, never credentials.
type agentSetupConnection struct {
	Name         string            `json:"name"`
	Hosts        []string          `json:"hosts"`
	Origins      []string          `json:"origins"`
	Placeholders map[string]string `json:"placeholders"`
	Git          []agentGitSlot    `json:"git"`
}

type agentGitSlot struct {
	Origin   string `json:"origin"`
	Path     string `json:"path"`
	Password string `json:"password"`
}

type agentSetup struct {
	Version     int                    `json:"version"`
	Identity    string                 `json:"identity"`
	CA          string                 `json:"ca"`
	Connections []agentSetupConnection `json:"http"`
}

func (m *monitor) discoveryHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /setup", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		ca := m.doc.Keys.CACert
		st := m.live.Load()
		m.mu.Unlock()
		p, ok := st.principals[key]
		if !ok {
			http.Error(w, "identity removed", http.StatusForbidden)
			return
		}
		result := agentSetup{Version: 1, Identity: p.Name, CA: ca, Connections: []agentSetupConnection{}}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			h, ok := c.connector.(*web.HTTP)
			if !ok || !p.reaches(c.account) {
				continue
			}
			setup := agentSetupConnection{Name: name, Hosts: h.Hosts, Origins: []string{}, Placeholders: map[string]string{}, Git: []agentGitSlot{}}
			for secret := range h.Names() {
				setup.Placeholders[secret] = web.Placeholder(name, secret)
			}
			for _, slot := range h.Slots {
				if !slices.Contains(setup.Origins, slot.Origin) {
					setup.Origins = append(setup.Origins, slot.Origin)
				}
				if slot.Basic == "password" && slot.Origin == "https://github.com" && setup.Placeholders[slot.Value] != "" {
					setup.Git = append(setup.Git, agentGitSlot{slot.Origin, slot.Path, setup.Placeholders[slot.Value]})
				}
			}
			result.Connections = append(result.Connections, setup)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(result)
	})
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
