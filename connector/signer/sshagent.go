package signer

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func ParseSSHAgent(config json.RawMessage) (*SSHAgent, error) {
	c := new(SSHAgent)
	return c, facts.DecodeNumbers(config, c)
}

const (
	msgUserAuthRequest = 50
)

var errAgentSignsOnly = errors.New("this agent only signs")

// SSHAgent signs with the private keys its credentials hold, each signature after the gate admits it.
type SSHAgent struct {
	Credentials []string `json:"credentials"`
}

type gatedAgent struct {
	agent.ExtendedAgent
	ctx  context.Context
	gate func(context.Context, facts.Event) error
}

func (keys *SSHAgent) Handler(secret func(ctx context.Context, name string) (string, error)) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, s net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		keys.serve(ctx, s, gate, secret)
	}
}

func (keys *SSHAgent) serve(ctx context.Context, s net.Conn, gate func(context.Context, facts.Event) error, secret func(context.Context, string) (string, error)) {
	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	for _, name := range keys.Credentials {
		encoded, err := secret(ctx, name)
		if err != nil {
			log.Print(err)
			return
		}
		key, err := ssh.ParseRawPrivateKey([]byte(encoded))
		if err != nil {
			log.Print(err)
			return
		}
		keyring.Add(agent.AddedKey{PrivateKey: key})
	}
	agent.ServeAgent(gatedAgent{keyring, ctx, gate}, s)
}

func (a gatedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if err := a.gate(a.ctx, facts.Capture(signEvent(key, data).Describe(), nil)); err != nil {
		return nil, err
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (gatedAgent) Add(agent.AddedKey) error   { return errAgentSignsOnly }
func (gatedAgent) Remove(ssh.PublicKey) error { return errAgentSignsOnly }
func (gatedAgent) RemoveAll() error           { return errAgentSignsOnly }
func (gatedAgent) Lock([]byte) error          { return errAgentSignsOnly }
func (gatedAgent) Unlock([]byte) error        { return errAgentSignsOnly }
func signEvent(key ssh.PublicKey, data []byte) *SignFacts {
	sign := &SignFacts{Agent: "ssh", Key: ssh.FingerprintSHA256(key), Purpose: "other"}
	var sig struct {
		Magic     [6]byte
		Namespace string
		Rest      []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(data, &sig) == nil && string(sig.Magic[:]) == "SSHSIG" {
		sign.Purpose, sign.Namespace = "sshsig", sig.Namespace
		return sign
	}
	var auth struct {
		Session []byte
		Type    byte
		User    string
		Rest    []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(data, &auth) == nil && auth.Type == msgUserAuthRequest {
		sign.Purpose, sign.User = "auth", auth.User
	}
	return sign
}
