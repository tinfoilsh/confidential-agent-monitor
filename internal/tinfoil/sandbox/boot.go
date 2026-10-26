package sandbox

import (
	"encoding/json"
	"errors"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Boot is what a sandbox must attest before Monitor logs in. Its persisted JSON
// matches the existing identity.sandbox source and owner API representation.
type Boot struct {
	Source     string `json:"source"`
	InstanceID string `json:"instance_id"`
}

func (b Boot) Validate() error {
	if _, _, digest, err := verify.ParseReference(b.Source); err != nil || digest == "" {
		return errors.New("source must be a digest-pinned release reference")
	}
	if b.InstanceID == "" {
		return errors.New("instance_id is required")
	}
	return nil
}

func decodeBoot(raw json.RawMessage) (b Boot, err error) {
	if len(raw) != 0 {
		err = facts.DecodeNumbers(raw, &b)
	}
	return
}

// ValidateMetadata checks the integration-owned portion of an identity before
// the host commits it. An absent boot is valid for ordinary agent identities.
func ValidateMetadata(raw json.RawMessage) error {
	b, err := decodeBoot(raw)
	if err == nil && b != (Boot{}) {
		err = b.Validate()
	}
	return err
}

// HTTP status belongs to the integration; the authenticated owner transport
// recognizes this narrow error capability without importing sandbox code.
type responseError struct {
	message string
	status  int
}

func (e responseError) Error() string   { return e.message }
func (e responseError) HTTPStatus() int { return e.status }
