package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

type identityEnrollment struct {
	Key        string                     `json:"key"`
	Routes     bool                       `json:"routes"`
	Restore    bool                       `json:"restore"`
	Attributes map[string]json.RawMessage `json:",embed"`
}

func (s held) enrollmentChanges(input map[string]identityEnrollment) ([]format.Change, error) {
	var changes []format.Change
	st := s.settings.Load()
	for name, id := range input {
		fingerprint, err := config.KeyFingerprint(id.Key)
		if err != nil {
			return nil, err
		}
		attributes := map[string]any{}
		for key, raw := range id.Attributes {
			if identityAttributes[key] == nil {
				return nil, fmt.Errorf("an enrollment has no field %s", key)
			}
			if attributes[key], err = facts.JSON[any](raw); err != nil {
				return nil, err
			}
		}
		maps.DeleteFunc(attributes, func(_ string, value any) bool { return value == nil })
		if principal, ok := st.Config.Principal(fingerprint); ok {
			existing := st.Identities[principal.Name]
			if id.Routes && !existing.Routes {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, format.Change{Path: []string{"identities", principal.Name, "routes"}, Value: true})
			}
			for key, value := range attributes {
				if before, _ := facts.JSON[any](existing.Attributes[key]); !reflect.DeepEqual(value, before) {
					changes = append(changes, format.Change{Path: []string{"identities", principal.Name, key}, Value: value})
				}
			}
			continue
		}
		if s.doc.Enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in the Perimeter")
		}
		if _, exists := st.Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Routes}
		maps.Copy(value, attributes)
		changes = append(changes, format.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

func (s *state) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	return s.enroll(ctx, map[string]identityEnrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Routes: true, Restore: true}})
}

func (s *state) enroll(ctx context.Context, identities map[string]identityEnrollment) error {
	return s.writeSettings(ctx, settingsWrite{derive: func(h held) ([]format.Change, error) { return h.enrollmentChanges(identities) }})
}
