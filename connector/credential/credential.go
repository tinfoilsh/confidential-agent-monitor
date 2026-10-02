package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Source supplies the current credential value to a connector.
type Source interface {
	Value(context.Context) (string, error)
}

// Static is a credential whose value does not expire.
type Static string

func (s Static) Value(context.Context) (string, error) { return string(s), nil }

// Fields identifies credential fields whose secret references survive config decoding.
// A * path segment addresses each entry of a map or array.
type Fields interface {
	CredentialFields() []string
}

// Store holds the shared sources for one account. Published stores are immutable.
type Store map[string]Source

// Credential is a named reference or an inline credential.
type Credential struct {
	Name *string
	Source
}

func (c *Credential) UnmarshalJSON(raw []byte) error {
	*c = Credential{}
	var ref map[string]json.RawMessage
	if json.Unmarshal(raw, &ref) == nil && len(ref) == 1 {
		if name, ok := ref["$secret"]; ok {
			if err := json.Unmarshal(name, &c.Name); err != nil {
				return err
			}
			if c.Name == nil {
				return errors.New("credential reference must be a string")
			}
			return nil
		}
	}
	var value *string
	if err := json.Unmarshal(raw, &value); err == nil && value != nil {
		c.Source = Static(*value)
		return nil
	}
	var v struct {
		OAuth *oauth `json:"oauth"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if v.OAuth == nil {
		return errors.New("credential must be a string or an oauth grant")
	}
	c.Source = newOAuth(*v.OAuth)
	return nil
}

func (c *Credential) Value(ctx context.Context, store Store) (string, error) {
	if c == nil {
		return "", errors.New("credential is not set")
	}
	source := c.Source
	if c.Name != nil {
		source = store[*c.Name]
		if source == nil {
			return "", fmt.Errorf("credential %q is not set", *c.Name)
		}
	}
	if source == nil {
		return "", errors.New("credential is not set")
	}
	return source.Value(ctx)
}
