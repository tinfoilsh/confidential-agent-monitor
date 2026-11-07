package signer

import (
	"errors"
	"log"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var SSHAgentKind = connector.Kind{Parse: parseSSHAgent, New: func() connector.Server { return new(SSHAgent) }}

func parseSSHAgent(source connector.Setup) (connector.Prepared, error) {
	c := new(sshAgentSetup)
	if err := connector.ParseSetup(source, c, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	return connector.Prepared{Value: c, SecretNames: c.Credentials}, nil
}

type SSHAgent struct{ connector.Slot[sshAgentSetup] }

const (
	msgUserAuthRequest = 50
)

var errAgentSignsOnly = errors.New("the Perimeter's agent only signs")

type sshAgentSetup struct {
	connector.SecretConfig
	Credentials []string `json:"credentials"`
}

type gatedAgent struct {
	semantics *connector.Semantics
	agent.ExtendedAgent
	s *connector.Stream
}

func (owner *SSHAgent) Serve(s *connector.Stream, _ *connector.Env) {
	keys, ok := owner.Load()
	if !ok {
		return
	}

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
	agent.ServeAgent(gatedAgent{&keys.Semantics, keyring, s}, s)
}

func (a gatedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if err := a.s.Gate(a.s.Context, a.semantics.Capture(signEvent(key, data).Describe())); err != nil {
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
