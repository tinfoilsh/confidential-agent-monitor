package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-policy-agent/opa/v1/util"
)

// input is the document every policy evaluates. Protocol layers are set by the relay that owns the event;
// decoded layers only when their decoder succeeded, so a rule can deny on their absence.
type input struct {
	Principal  principal `json:"principal"`
	Connection string    `json:"connection,omitempty"`
	Protocol   string    `json:"protocol"`
	event
}

type principal struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type event struct {
	TCP      *tcpLayer      `json:"tcp,omitempty"`
	HTTP     *httpLayer     `json:"http,omitempty"`
	SSH      *sshLayer      `json:"ssh,omitempty"`
	IMAP     *imapLayer     `json:"imap,omitempty"`
	SMTP     *smtpLayer     `json:"smtp,omitempty"`
	Sign     *signLayer     `json:"sign,omitempty"`
	Postgres *postgresLayer `json:"postgres,omitempty"`
	Redis    *argvLayer     `json:"redis,omitempty"`

	GraphQL *graphqlLayer `json:"graphql,omitempty"`
	Command *argvLayer    `json:"command,omitempty"`
	Mail    *mailLayer    `json:"mail,omitempty"`
	Payload *gitLayer     `json:"payload,omitempty"`
}

type tcpLayer struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

// httpLayer is the request before substitution; secrets names the placeholders it carried.
type httpLayer struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Query   url.Values  `json:"query"`
	Headers http.Header `json:"headers"`
	Secrets []string    `json:"secrets"`
	Body    any         `json:"body,omitempty"`
}

type sshLayer struct {
	Request   string  `json:"request"`
	Command   string  `json:"command,omitempty"`
	Subsystem string  `json:"subsystem,omitempty"`
	Term      string  `json:"term,omitempty"`
	Env       *sshEnv `json:"env,omitempty"`
}

type sshEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type imapLayer struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Mailbox string `json:"mailbox,omitempty"`
}

type smtpLayer struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

// signLayer is a signature an agent was asked for: by ssh with a purpose, or by gpg with a keygrip and digest.
type signLayer struct {
	Agent     string `json:"agent"`
	Key       string `json:"key,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	User      string `json:"user,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Op        string `json:"op,omitempty"`
}

type postgresLayer struct {
	SQL string `json:"sql"`
}

type argvLayer struct {
	Argv []string `json:"argv"`
}

type graphqlLayer struct {
	Kind  string   `json:"kind"`
	Roots []string `json:"roots"`
}

type mailLayer struct {
	From        []string `json:"from"`
	To          []string `json:"to"`
	Cc          []string `json:"cc"`
	Subject     string   `json:"subject"`
	Attachments []string `json:"attachments"`
}

type gitLayer struct {
	Type       string   `json:"type"`
	Tree       string   `json:"tree,omitempty"`
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"`
	Tag        string   `json:"tag,omitempty"`
	Parents    []string `json:"parents"`
	Author     string   `json:"author,omitempty"`
	Committer  string   `json:"committer,omitempty"`
	Tagger     string   `json:"tagger,omitempty"`
	Message    string   `json:"message"`
}

// gate evaluates one event on this channel. The error carries the message of every rule that denied it.
func (cc *channelConn) gate(e event) error {
	encoded, err := json.Marshal(input{cc.principal, cc.name, cc.protocol, e})
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := util.UnmarshalJSON(encoded, &doc); err != nil {
		return err
	}
	denied, err := cc.m.policy.Deny(context.Background(), doc)
	if err != nil {
		log.Printf("policy: %v", err)
		return err
	}
	if len(denied) == 0 {
		return nil
	}
	reason := strings.Join(denied, "; ")
	log.Printf("denied %s: %s", encoded, reason)
	return errors.New(reason)
}
