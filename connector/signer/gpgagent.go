package signer

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
)

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

type GPGAgent string

func (socket *GPGAgent) Serve(s *connector.Stream, _ *connector.Env) {
	up, err := (&net.Dialer{Timeout: connector.DialTimeout}).DialContext(s.Context, "unix", string(*socket))
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
			if err := s.Gate(&sign); err != nil {
				fmt.Fprintf(s, "ERR %d %v <Monitor>\n", assuanNotSupported, err)
				continue
			}
		}
		if _, err := fmt.Fprintf(up, "%s\n", line); err != nil {
			return
		}
	}
}
