package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
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

type identity struct {
	Key         string   `json:"key"`
	Connections []string `json:"connections"`
}

// Connector entries are decoded as YAML, which JSON is a subset of.
type config struct {
	AllowNetworks []netip.Prefix                        `json:"allow_networks"`
	Identities    map[string]identity                   `json:"identities"`
	Connections   map[string]map[string]json.RawMessage `json:"connections"`
	MCP           map[string]json.RawMessage            `json:"mcp"`
	Policies      map[string]string                     `json:"policies"`
	Data          map[string]any                        `json:"data"`
	Pins          map[string]*sentinel.Snapshot         `json:"pins"`
}

type connection struct {
	name, protocol string
	connector      connector.Connector
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address, opened after unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucket := flag.String("bucket", "", "blob URL holding the encrypted state")
	object := flag.String("object", "monitor.enc", "key of the encrypted state")
	flag.Parse()
	if err := run(*listen, *api, *bucket, *object, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(listen, api, bucketURL, object string, args []string) error {
	if len(args) == 1 && args[0] == "env" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		_, connections, _, err := parse(raw)
		if err != nil {
			return err
		}
		for name, c := range connections {
			r, ok := c.connector.(*web.HTTP)
			if !ok {
				continue
			}
			for secret := range r.Secrets {
				fmt.Printf("export %s=%s\n", secret, web.Placeholder(name, secret))
			}
		}
		return nil
	}
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
func parse(raw []byte) (*config, map[string]*connection, map[string]*mcpServer, error) {
	var cfg config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, nil, nil, err
	}
	connections := map[string]*connection{}
	for name, kinds := range cfg.Connections {
		if name == gatewayName {
			return nil, nil, nil, fmt.Errorf("connection name %s is reserved", name)
		}
		if len(kinds) != 1 {
			return nil, nil, nil, fmt.Errorf("connection %s must have one kind", name)
		}
		for kind, raw := range kinds {
			newConnector, ok := connectorKinds[kind]
			if !ok {
				return nil, nil, nil, fmt.Errorf("connection %s has unknown kind %s", name, kind)
			}
			c := &connection{name: name, protocol: kind, connector: newConnector()}
			if err := yaml.Unmarshal(raw, c.connector); err != nil {
				return nil, nil, nil, fmt.Errorf("connection %s: %w", name, err)
			}
			connections[name] = c
		}
	}
	servers := map[string]*mcpServer{}
	for name, raw := range cfg.MCP {
		servers[name] = new(mcpServer)
		if err := yaml.Unmarshal(raw, servers[name]); err != nil {
			return nil, nil, nil, fmt.Errorf("mcp %s: %w", name, err)
		}
	}
	return &cfg, connections, servers, nil
}
