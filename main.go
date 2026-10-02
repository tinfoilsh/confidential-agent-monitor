package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/email"
	"github.com/tinfoilsh/monitor/connector/postgres"
	"github.com/tinfoilsh/monitor/connector/redis"
	"github.com/tinfoilsh/monitor/connector/session"
	"github.com/tinfoilsh/monitor/connector/signer"
	"github.com/tinfoilsh/monitor/connector/web"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/s3blob"
	"gopkg.in/yaml.v3"
)

const devBucket = "file://"

// The kind is also the protocol policies see.
var connectorKinds = map[string]func() connector.Connector{
	"http":      func() connector.Connector { return new(web.HTTP) },
	"ssh":       func() connector.Connector { return new(session.SSH) },
	"cli":       func() connector.Connector { return new(session.CLI) },
	"ssh-agent": func() connector.Connector { return new(signer.SSHAgent) },
	"gpg-agent": func() connector.Connector { return new(signer.GPGAgent) },
	"imap":      func() connector.Connector { return new(email.IMAP) },
	"smtp":      func() connector.Connector { return new(email.SMTP) },
	"postgres":  func() connector.Connector { return new(postgres.Postgres) },
	"redis":     func() connector.Connector { return new(redis.Redis) },
}

const secretRef = "$secret"

var (
	audiences = []string{"me", "team", "anyone"}
	levels    = []string{"off", "read", "ask", "allow"}
)

type identity struct {
	Key      string            `json:"key"`
	Accounts map[string]access `json:"accounts"`
	Rules    []rule            `json:"rules,omitempty"`
}

type access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
}

type rule struct {
	Account string         `json:"account"`
	Action  string         `json:"action"`
	Scope   map[string]any `json:"scope"`
	Waives  []string       `json:"waives"`
}

// Connector entries are decoded as YAML, which JSON is a subset of.
type account struct {
	Template    string                    `json:"template"`
	Fields      map[string]any            `json:"fields,omitempty"`
	Contents    string                    `json:"contents"`
	Strangers   bool                      `json:"strangers"`
	Sends       string                    `json:"sends"`
	Connections map[string]map[string]any `json:"connections,omitempty"`
}

type config struct {
	AllowNetworks []netip.Prefix                `json:"allow_networks"`
	Accounts      map[string]account            `json:"accounts"`
	Identities    map[string]identity           `json:"identities"`
	Policies      map[string]string             `json:"policies"`
	Data          map[string]any                `json:"data"`
	Pins          map[string]*sentinel.Snapshot `json:"pins"`
}

type connection struct {
	name, protocol, account string
	connector               connector.Connector
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address, opened after unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucket := flag.String("bucket", "", "blob URL holding the encrypted state")
	object := flag.String("object", "monitor.enc", "key of the encrypted state")
	flag.Parse()
	if err := run(*listen, *api, *bucket, *object); err != nil {
		log.Fatal(err)
	}
}

func run(listen, api, bucketURL, object string) error {
	if !strings.HasPrefix(bucketURL, devBucket) {
		delete(connectorKinds, "cli")
		delete(connectorKinds, "gpg-agent")
	}
	bucket, err := blob.OpenBucket(context.Background(), bucketURL)
	if err != nil {
		return err
	}
	m := &monitor{store: bucket, object: object, listen: listen, gateway: connector.NewListener()}
	return (&http.Server{Addr: api, Handler: m.handler(), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe()
}

// parse decodes the owner's config without starting anything.
func parse(raw []byte, secrets map[string]map[string]any) (*config, map[string]*connection, map[string]*mcpServer, error) {
	var cfg config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, nil, nil, err
	}
	connections := map[string]*connection{}
	servers := map[string]*mcpServer{}
	for acct, a := range cfg.Accounts {
		if _, err := fs.Stat(templates, templateDir+"/"+a.Template+".rego"); err != nil {
			return nil, nil, nil, fmt.Errorf("account %s has unknown template %s", acct, a.Template)
		}
		if !slices.Contains(audiences, a.Contents) || !slices.Contains(audiences, a.Sends) {
			return nil, nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, audiences)
		}
		for key, kinds := range a.Connections {
			name := acct
			if key != "" {
				name += "-" + key
			}
			if name == gatewayName || connections[name] != nil || servers[name] != nil {
				return nil, nil, nil, fmt.Errorf("connection name %s is reserved or taken", name)
			}
			if len(kinds) != 1 {
				return nil, nil, nil, fmt.Errorf("connection %s must have one kind", name)
			}
			for kind, spec := range kinds {
				spec, err := resolve(spec, secrets[acct])
				if err != nil {
					return nil, nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				raw, err := json.Marshal(spec)
				if err != nil {
					return nil, nil, nil, err
				}
				if kind == protocolMCP {
					servers[name] = &mcpServer{account: acct}
					if err := yaml.Unmarshal(raw, servers[name]); err != nil {
						return nil, nil, nil, fmt.Errorf("connection %s: %w", name, err)
					}
					continue
				}
				newConnector, ok := connectorKinds[kind]
				if !ok {
					return nil, nil, nil, fmt.Errorf("connection %s has unknown kind %s", name, kind)
				}
				c := &connection{name: name, protocol: kind, account: acct, connector: newConnector()}
				if err := yaml.Unmarshal(raw, c.connector); err != nil {
					return nil, nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				connections[name] = c
			}
		}
	}
	for name, id := range cfg.Identities {
		for acct, a := range id.Accounts {
			if _, ok := cfg.Accounts[acct]; !ok || !slices.Contains(levels, a.Level) {
				return nil, nil, nil, fmt.Errorf("identity %s: account %s must exist and have a level in %v", name, acct, levels)
			}
			for action, level := range a.Actions {
				if level == "read" || !slices.Contains(levels, level) {
					return nil, nil, nil, fmt.Errorf("identity %s: action %s must be off, ask or allow", name, action)
				}
			}
		}
	}
	return &cfg, connections, servers, nil
}

// resolve replaces each {"$secret": key} with the account's secret, which may be an object.
func resolve(v any, secrets map[string]any) (any, error) {
	var err error
	switch v := v.(type) {
	case map[string]any:
		if key, ok := v[secretRef].(string); ok && len(v) == 1 {
			if secret, ok := secrets[key]; ok {
				return secret, nil
			}
			return nil, fmt.Errorf("secret %s is not set", key)
		}
		for k, e := range v {
			if v[k], err = resolve(e, secrets); err != nil {
				return nil, err
			}
		}
	case []any:
		for i, e := range v {
			if v[i], err = resolve(e, secrets); err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}
