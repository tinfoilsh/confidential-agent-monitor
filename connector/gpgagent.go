package connector

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

const (
	agentGPG           = "gpg"
	assuanNotSupported = 536870981
)

// agentCommands use a key without moving it. Everything else is answered with an error here.
var agentCommands = map[string]bool{
	"OPTION": true, "RESET": true, "BYE": true, "NOP": true, "GETINFO": true, "HAVEKEY": true,
	"KEYINFO": true, "READKEY": true, "SIGKEY": true, "SETKEY": true, "SETKEYDESC": true,
	"SETHASH": true, "PKSIGN": true, "PKDECRYPT": true,
}

// GPGAgent is the socket of a real gpg-agent, proxied with a gate before each signature or decryption.
type GPGAgent string

func (socket *GPGAgent) Serve(s *Stream) {
	defer s.Close()
	up, err := net.DialTimeout("unix", string(*socket), dialTimeout)
	if err != nil {
		log.Printf("gpg-agent: %v", err)
		return
	}
	defer up.Close()
	go func() {
		io.Copy(s, up)
		s.Close()
	}()
	sign := signLayer{Agent: agentGPG}
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
			sign = signLayer{Agent: agentGPG}
		case command == "SIGKEY" || command == "SETKEY":
			sign.Key = rest
		case command == "SETHASH":
			sign.Hash = rest
		case command == "PKSIGN" || command == "PKDECRYPT":
			sign.Op = strings.ToLower(command)
			if err := s.Gate(Event{Sign: &sign}); err != nil {
				fmt.Fprintf(s, "ERR %d %v <Monitor>\n", assuanNotSupported, err)
				continue
			}
		}
		if _, err := fmt.Fprintf(up, "%s\n", line); err != nil {
			return
		}
	}
}
