package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	agentSSH           = "ssh"
	agentGPG           = "gpg"
	sshsigMagic        = "SSHSIG"
	purposeSSHSig      = "sshsig"
	purposeAuth        = "auth"
	purposeOther       = "other"
	msgUserAuthRequest = 50
	assuanNotSupported = 536870981
)

var errAgentSignsOnly = errors.New("the monitor's agent only signs")

// sshAgentRelay is the private key files of a keyring that only signs.
type sshAgentRelay []string

// gatedAgent asks the policy before each signature.
type gatedAgent struct {
	agent.ExtendedAgent
	cc *channelConn
}

func (keys *sshAgentRelay) serve(cc *channelConn) {
	defer cc.Close()
	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	for _, path := range *keys {
		encoded, err := os.ReadFile(path)
		if err != nil {
			log.Print(err)
			return
		}
		key, err := ssh.ParseRawPrivateKey(encoded)
		if err != nil {
			log.Printf("%s: %v", path, err)
			return
		}
		keyring.Add(agent.AddedKey{PrivateKey: key})
	}
	agent.ServeAgent(gatedAgent{keyring, cc}, cc)
}

func (a gatedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a gatedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if err := a.cc.gate(event{Sign: signEvent(key, data)}); err != nil {
		return nil, err
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (gatedAgent) Add(agent.AddedKey) error   { return errAgentSignsOnly }
func (gatedAgent) Remove(ssh.PublicKey) error { return errAgentSignsOnly }
func (gatedAgent) RemoveAll() error           { return errAgentSignsOnly }
func (gatedAgent) Lock([]byte) error          { return errAgentSignsOnly }
func (gatedAgent) Unlock([]byte) error        { return errAgentSignsOnly }
func (gatedAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// signEvent names what a signature is for: an SSHSIG namespace, a user authentication, or something else.
func signEvent(key ssh.PublicKey, data []byte) *signLayer {
	sign := &signLayer{Agent: agentSSH, Key: ssh.FingerprintSHA256(key), Purpose: purposeOther}
	var sig struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		Hash      string
		Digest    string
	}
	if ssh.Unmarshal(data, &sig) == nil && string(sig.Magic[:]) == sshsigMagic {
		sign.Purpose, sign.Namespace = purposeSSHSig, sig.Namespace
		return sign
	}
	var auth struct {
		Session               []byte
		Type                  byte
		User, Service, Method string
		HasSignature          bool
		Algorithm             string
		Key                   []byte
	}
	if ssh.Unmarshal(data, &auth) == nil && auth.Type == msgUserAuthRequest {
		sign.Purpose, sign.User = purposeAuth, auth.User
	}
	return sign
}

// agentCommands use a key without moving it. Everything else is answered with an error here.
var agentCommands = map[string]bool{
	"OPTION": true, "RESET": true, "BYE": true, "NOP": true, "GETINFO": true, "HAVEKEY": true,
	"KEYINFO": true, "READKEY": true, "SIGKEY": true, "SETKEY": true, "SETKEYDESC": true,
	"SETHASH": true, "PKSIGN": true, "PKDECRYPT": true,
}

// gpgAgentRelay is the socket of a real gpg-agent, proxied with a gate before each signature or decryption.
type gpgAgentRelay string

func (socket *gpgAgentRelay) serve(cc *channelConn) {
	defer cc.Close()
	up, err := net.DialTimeout("unix", string(*socket), dialTimeout)
	if err != nil {
		log.Printf("gpg-agent: %v", err)
		return
	}
	defer up.Close()
	go func() {
		io.Copy(cc, up)
		cc.Close()
	}()
	sign := signLayer{Agent: agentGPG}
	lines := bufio.NewScanner(cc)
	for lines.Scan() {
		line := lines.Text()
		word, rest, _ := strings.Cut(line, " ")
		command := strings.ToUpper(word)
		switch {
		case command == "D" || command == "END" || command == "CAN" || strings.HasPrefix(line, "#"):
		case !agentCommands[command]:
			fmt.Fprintf(cc, "ERR %d Not supported <Monitor>\n", assuanNotSupported)
			continue
		case command == "RESET":
			sign = signLayer{Agent: agentGPG}
		case command == "SIGKEY" || command == "SETKEY":
			sign.Key = rest
		case command == "SETHASH":
			sign.Hash = rest
		case command == "PKSIGN" || command == "PKDECRYPT":
			sign.Op = strings.ToLower(command)
			if err := cc.gate(event{Sign: &sign}); err != nil {
				fmt.Fprintf(cc, "ERR %d %v <Monitor>\n", assuanNotSupported, err)
				continue
			}
		}
		if _, err := fmt.Fprintf(up, "%s\n", line); err != nil {
			return
		}
	}
}
