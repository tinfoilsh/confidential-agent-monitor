package monitor

import (
	"encoding/json"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
)

type decisionInput struct {
	Facts         json.RawMessage    `json:"facts"` // the bytes the audit record stores
	Authorization authorizationInput `json:"authorization"`
	Connection    connectionInput    `json:"connection"`
}

type authorizationInput struct {
	Access             config.Access       `json:"access"`
	Reaches            bool                `json:"reaches"`
	Effects            []map[string]string `json:"effects"` // global, connection, identity, access
	AllowPaidInference bool                `json:"allow_paid_inference"`
	Rules              []config.Rule       `json:"rules"`
	Approved           []string            `json:"approved"`
	Grant              map[string]any      `json:"grant"`
}

type connectionInput struct {
	Contents    string   `json:"contents"`
	Strangers   bool     `json:"strangers"`
	Sends       string   `json:"sends"`
	Private     []string `json:"private"`
	PublicScope []string `json:"public_scope"`
}

type adminCall struct {
	Caller policyCaller `json:"caller"`
	Route  string       `json:"route"`
	Answer any          `json:"answer,omitempty"`
	Record any          `json:"record,omitempty"`
}

type policyCaller struct {
	Name   string         `json:"name"`
	Owner  bool           `json:"owner"`
	Claims map[string]any `json:"claims"`
}

type capabilityInput struct {
	Principal  facts.Principal `json:"principal"`
	Routes     bool            `json:"routes"`
	Capability string          `json:"capability"`
}
