package migrate

import (
	"encoding/json"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
)

const (
	legacyApproved     = "approved"
	legacyOwnerService = "admin"
	stateRefused       = "refused"
	causeInvalid       = "invalid"
	causePrecondition  = "precondition"
	causeDenied        = "denied"
)

type refusal struct {
	Cause   string   `json:"cause"`
	Reasons []string `json:"reasons,omitempty"`
}

// Record rewrites an audit or pending record stored before version 5 in the current shape; any other record is returned as it is.
func Record(line []byte) ([]byte, error) {
	var old struct {
		State        string               `json:"state"`
		Grant        json.RawMessage      `json:"grant"`
		Allow        *bool                `json:"allow"`
		Deny         []string             `json:"deny"`
		Requirements []config.Requirement `json:"requirements"`
		Sends        string               `json:"sends"`
		Next         format.Label         `json:"next"`
		Invalid      bool                 `json:"invalid"`
		Expires      string               `json:"expires"`
		Facts        struct {
			Service    string `json:"service"`
			Connection string `json:"connection"`
		} `json:"facts"`
	}
	var r map[string]json.RawMessage
	err := json.Unmarshal(line, &old)
	if err == nil && old.Allow != nil {
		err = json.Unmarshal(line, &r)
	}
	if err != nil || old.Allow == nil {
		return line, err
	}
	for _, key := range []string{"grant", "allow", "deny", "requirements", "sends", "next", "invalid"} {
		delete(r, key)
	}
	set := func(key string, value any) { r[key], _ = json.Marshal(value) }
	set("scope", old.Grant)
	// A refused request the policy allowed, or asked about and waited on, failed a precondition that settleRecord kept in deny.
	failed := old.State == stateRefused && (*old.Allow || len(old.Requirements) != 0 && old.Expires != "")
	switch {
	case old.Facts.Service == legacyOwnerService && old.Facts.Connection == "":
		r["facts"] = ownerFacts(r["facts"])
		if old.State == stateRefused {
			set("refusal", refusal{causePrecondition, old.Deny})
		}
	case old.Invalid:
		set("refusal", refusal{causeInvalid, old.Deny})
	case len(old.Deny) != 0 && !failed:
		set("decision", config.Decision{Outcome: config.OutcomeDeny, Sends: old.Sends, Reasons: old.Deny})
		if old.State == stateRefused {
			set("refusal", refusal{Cause: causeDenied})
		}
	case len(old.Requirements) != 0:
		set("decision", config.Decision{Outcome: config.OutcomeAsk, Sends: old.Sends, Gaps: old.Requirements})
	case *old.Allow:
		set("decision", config.Decision{Outcome: config.OutcomeAllow, Sends: old.Sends, Next: &old.Next})
	}
	if failed {
		set("refusal", refusal{causePrecondition, old.Deny})
	}
	if old.State == legacyApproved {
		set("state", "allowed")
	}
	return json.Marshal(r)
}

// An admin action without a named caller was the owner's, such as an unlock.
func ownerFacts(raw json.RawMessage) json.RawMessage {
	var f, principal map[string]json.RawMessage
	if json.Unmarshal(raw, &f) != nil {
		return raw
	}
	var name string
	if json.Unmarshal(f["principal"], &principal); principal == nil {
		principal = map[string]json.RawMessage{}
	}
	if json.Unmarshal(principal["name"], &name); name == "" {
		principal["name"], _ = json.Marshal(config.OwnerName)
	}
	f["principal"], _ = json.Marshal(principal)
	f["connection"], _ = json.Marshal(config.PerimeterConnection)
	f["service"] = f["connection"]
	upgraded, err := json.Marshal(f)
	if err != nil {
		return raw
	}
	return upgraded
}
