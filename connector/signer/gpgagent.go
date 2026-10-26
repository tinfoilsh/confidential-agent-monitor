package signer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
)

var GPGAgentDefinition = connector.Definition{Parse: parseGPGAgent, New: func() connector.Server { return new(GPGAgent) }}

func parseGPGAgent(source connector.Setup) (connector.Prepared, error) {
	c := new(gpgAgentSetup)
	if err := connector.ParseSetup(source, c, &c.Semantics, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	return connector.Prepared{Source: source, Value: c}, nil
}

// GPGAgent keeps one immutable setup for each admitted stream.
type GPGAgent struct{ connector.Slot[gpgAgentSetup] }

const (
	agentGPG           = "gpg"
	assuanNotSupported = 536870981
)

// agentCommands use a key without moving it.
var agentCommands = map[string]bool{
	"OPTION": true, "RESET": true, "BYE": true, "NOP": true, "GETINFO": true, "HAVEKEY": true,
	"KEYINFO": true, "READKEY": true, "SIGKEY": true, "SETKEY": true, "SETKEYDESC": true,
	"SETHASH": true, "PKSIGN": true, "PKDECRYPT": true,
}

type gpgAgentSetup struct {
	connector.Semantics
	socket string
}

func (s *gpgAgentSetup) UnmarshalJSON(raw []byte) error { return json.Unmarshal(raw, &s.socket) }

func (owner *GPGAgent) Serve(s *connector.Stream, _ *connector.Env) {
	captured := owner.Load()
	if captured == nil {
		return
	}
	socket := captured.Value

	up, err := (&net.Dialer{Timeout: connector.DialTimeout}).DialContext(s.Context, "unix", socket.socket)
	if err != nil {
		log.Printf("gpg-agent: %v", err)
		return
	}
	defer s.Interrupt(up)()
	defer connector.PumpReplies(s, func() { io.Copy(s, up) })()
	sign := Request{Agent: agentGPG}
	lines := bufio.NewScanner(s)
	for lines.Scan() {
		line := lines.Text()
		word, rest, _ := strings.Cut(line, " ")
		command := strings.ToUpper(word)
		switch {
		case command == "D" || command == "END" || command == "CAN" || strings.HasPrefix(line, "#"):
		case !agentCommands[command]:
			fmt.Fprintf(s, "ERR %d Not supported <Monitor>\n", assuanNotSupported)
			continue
		case command == "RESET":
			sign = Request{Agent: agentGPG}
		case command == "SIGKEY" || command == "SETKEY":
			sign.Key = rest
		case command == "SETHASH":
			sign.Hash = rest
		case command == "PKSIGN" || command == "PKDECRYPT":
			sign.Op = strings.ToLower(command)
			if err := s.Gate(s.Context, socket.Event((&sign).Describe())); err != nil {
				fmt.Fprintf(s, "ERR %d %v <Monitor>\n", assuanNotSupported, err)
				continue
			}
		}
		if _, err := fmt.Fprintf(up, "%s\n", line); err != nil {
			return
		}
	}
}
