package migrate

import (
	"encoding/json"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"golang.org/x/crypto/ssh"
)

// Before version 4 a label belonged to a key. A certified key's name is not stored, so its label is dropped.
func upgradeV3(plain []byte) ([]byte, error) {
	var v3 struct {
		Version int                     `json:"version"`
		Policy  string                  `json:"policy"`
		Labels  map[string]format.Label `json:"labels"`
	}
	if err := json.Unmarshal(plain, &v3); err != nil {
		return nil, err
	}
	if v3.Version >= version4 {
		return plain, nil
	}
	source, err := tomledit.Read(v3.Policy)
	if err != nil {
		return nil, err
	}
	identities, _ := source["identities"].(map[string]any)
	labels := map[string]format.Label{}
	for name, value := range identities {
		identity, _ := value.(map[string]any)
		authorized, _ := identity["key"].(string)
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized)); err == nil {
			if l, ok := v3.Labels[ssh.FingerprintSHA256(key)]; ok {
				labels[name] = l
			}
		}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, err
	}
	doc["version"], _ = json.Marshal(version4)
	doc["labels"], _ = json.Marshal(labels)
	return json.Marshal(doc)
}
