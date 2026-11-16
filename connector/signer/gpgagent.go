package signer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

func ParseGPGAgent(config json.RawMessage) (*GPGAgent, error) {
	c := new(GPGAgent)
	return c, facts.DecodeNumbers(config, &c.socket)
}

const (
	agentGPG           = "gpg"
	assuanNotSupported = 536870981
)

var agentCommands = map[string]bool{
	"OPTION": true, "RESET": true, "BYE": true, "NOP": true, "GETINFO": true, "HAVEKEY": true,
	"KEYINFO": true, "READKEY": true, "SIGKEY": true, "SETKEY": true, "SETKEYDESC": true,
	"SETHASH": true, "PKSIGN": true, "PKDECRYPT": true,
}

type GPGAgent struct{ socket string }

func (socket *GPGAgent) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error)) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, s net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		socket.serve(ctx, cancel, s, gate, dial)
	}
}

func (socket *GPGAgent) serve(ctx context.Context, cancel func(), s net.Conn, gate func(context.Context, facts.Event) error, dial func(context.Context, string, string) (net.Conn, error)) {
	up, err := dial(ctx, "unix", socket.socket)
	if err != nil {
		log.Printf("gpg-agent: %v", err)
		return
	}
	stop := context.AfterFunc(ctx, func() { up.Close() })
	defer func() { stop(); up.Close() }()
	pumped := make(chan struct{})
	go func() { defer close(pumped); io.Copy(s, up); cancel(); s.Close() }()
	defer func() { cancel(); s.Close(); <-pumped }()
	sign := SignFacts{Agent: agentGPG}
	lines := bufio.NewScanner(s)
	for lines.Scan() {
		line := lines.Text()
		word, rest, _ := strings.Cut(line, " ")
		command := strings.ToUpper(word)
		switch {
		case command == "D" || command == "END" || command == "CAN" || strings.HasPrefix(line, "#"):
		case !agentCommands[command]:
			fmt.Fprintf(s, "ERR %d Not supported <proxy>\n", assuanNotSupported)
			continue
		case command == "RESET":
			sign = SignFacts{Agent: agentGPG}
		case command == "SIGKEY" || command == "SETKEY":
			sign.Key = rest
		case command == "SETHASH":
			sign.Hash = rest
		case command == "PKSIGN" || command == "PKDECRYPT":
			sign.Op = strings.ToLower(command)
			if err := gate(ctx, facts.Capture(sign.Describe(), nil)); err != nil {
				fmt.Fprintf(s, "ERR %d %v <proxy>\n", assuanNotSupported, err)
				continue
			}
		}
		if _, err := fmt.Fprintf(up, "%s\n", line); err != nil {
			return
		}
	}
}
