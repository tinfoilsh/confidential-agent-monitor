package signer

import (
	"errors"
	"log"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	msgUserAuthRequest = 50
)

var errAgentSignsOnly = errors.New("the monitor's agent only signs")

type SSHAgent struct {
	connector.SecretConfig
}

type gatedAgent struct {
	agent.ExtendedAgent
	s *connector.Stream
}

func (keys *SSHAgent) Serve(s *connector.Stream, _ *connector.Env) {
	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	for _, value := range keys.Secrets {
		encoded, err := value.Value(s.Context)
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
	agent.ServeAgent(gatedAgent{keyring, s}, s)
}

func (a gatedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if err := a.s.Gate(signEvent(key, data)); err != nil {
		return nil, err
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (gatedAgent) Add(agent.AddedKey) error   { return errAgentSignsOnly }
func (gatedAgent) Remove(ssh.PublicKey) error { return errAgentSignsOnly }
func (gatedAgent) RemoveAll() error           { return errAgentSignsOnly }
func (gatedAgent) Lock([]byte) error          { return errAgentSignsOnly }
func (gatedAgent) Unlock([]byte) error        { return errAgentSignsOnly }
func signEvent(key ssh.PublicKey, data []byte) *Request {
	sign := &Request{Agent: "ssh", Key: ssh.FingerprintSHA256(key), Purpose: "other"}
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
