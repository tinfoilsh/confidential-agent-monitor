// Package facts defines the request data shared by connectors, policy, and audit.
package facts

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// Version identifies the public facts schema.
const Version = 4

// Label levels are ordered from most restrictive to least restrictive.
// Policy derives its rank tables from these same lists.
var (
	Audiences = []string{"me", "team", "anyone"}
	Trusts    = []string{"untrusted", "trusted"}
)

type Kind string

const (
	KindOperation Kind = "operation"
	KindAdmission Kind = "admission"
	KindMessage   Kind = "message"
)

type Principal struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type Label struct {
	Audience string            `json:"audience"`
	Trust    string            `json:"trust"`
	Because  map[string]string `json:"because,omitempty"`
}

func (l Label) Valid() bool {
	return slices.Contains(Audiences, l.Audience) && slices.Contains(Trusts, l.Trust)
}

type Operation struct {
	ID            string   `json:"id"`
	Action        string   `json:"action"`
	Effects       []string `json:"effects"`
	RequiresTrust bool     `json:"requires_trust"`
}

type Context struct {
	Label    Label  `json:"label"`
	Sends    string `json:"sends"`
	Observes Label  `json:"observes"`
	Cause    string `json:"cause"`
	Channel  *Label `json:"channel,omitempty"`
}

// Facts is the snapshot shared by authorization and audit.
// Connectors supply protocol details using their own types.
type Facts struct {
	Version    int            `json:"version"`
	Kind       Kind           `json:"kind"`
	Principal  Principal      `json:"principal"`
	Account    string         `json:"account"`
	Service    string         `json:"service"`
	Connection string         `json:"connection"`
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	Context    Context        `json:"context"`
	Title      string         `json:"title"`
	Details    map[string]any `json:"details"`
}

// Obligations describes the requirements carried by an effect.
type Obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"`
	Discloses bool `json:"discloses"`
}

// Effects is shared by preset validation, request descriptions, policy, and UI.
var Effects = map[string]Obligations{
	"read":     {},
	"session":  {},
	"write":    {Change: true},
	"generate": {Change: true},
	"delete":   {Change: true, Trust: true},
	"admin":    {Change: true, Trust: true},
	"execute":  {Change: true, Trust: true},
	"send":     {Change: true, Trust: true, Discloses: true},
	"share":    {Change: true, Trust: true, Discloses: true},
	"publish":  {Change: true, Trust: true, Ask: true, Discloses: true},
	"pay":      {Change: true, Trust: true, Ask: true},
}

func ValidEffects(effects []string) bool {
	if len(effects) == 0 {
		return false
	}
	for _, effect := range effects {
		if _, ok := Effects[effect]; !ok {
			return false
		}
	}
	return true
}

// ObligationsFor combines the requirements of all effects on an operation.
func ObligationsFor(effects []string) (out Obligations) {
	for _, effect := range effects {
		o := Effects[effect]
		out.Change = out.Change || o.Change
		out.Trust = out.Trust || o.Trust
		out.Ask = out.Ask || o.Ask
		out.Discloses = out.Discloses || o.Discloses
	}
	return out
}

// Observe joins request observations and mailbox history, preserving provenance
// on axes that do not become more restrictive. Both labels must be valid.
func (l Label) Observe(observed Label, cause string) Label {
	l.Because = maps.Clone(l.Because)
	if l.Because == nil {
		l.Because = map[string]string{}
	}
	if slices.Index(Audiences, observed.Audience) < slices.Index(Audiences, l.Audience) {
		l.Audience, l.Because["audience"] = observed.Audience, cause
	}
	if slices.Index(Trusts, observed.Trust) < slices.Index(Trusts, l.Trust) {
		l.Trust, l.Because["trust"] = observed.Trust, cause
	}
	return l
}

// Validate checks the resolved snapshot for every connector before policy
// runs. Unknown requests have no operation; malformed descriptions are denied.
func (f Facts) Validate() error {
	var errs []error
	if !slices.Contains([]Kind{KindOperation, KindAdmission, KindMessage}, f.Kind) {
		errs = append(errs, fmt.Errorf("invalid request kind %q", f.Kind))
	}
	if op := f.Operation; op != nil && (op.ID == "" || op.Action == "" || !ValidEffects(op.Effects)) {
		errs = append(errs, errors.New("the recognized operation is malformed"))
	}
	if !f.Context.Label.Valid() {
		errs = append(errs, errors.New("the agent label is invalid"))
	}
	if !f.Context.Observes.Valid() {
		errs = append(errs, errors.New("the observation label is invalid"))
	}
	if !slices.Contains(Audiences, f.Context.Sends) {
		errs = append(errs, errors.New("the disclosure audience is invalid"))
	}
	if channel := f.Context.Channel; channel != nil && !channel.Valid() {
		errs = append(errs, errors.New("the message channel label is invalid"))
	}
	if f.Kind == KindMessage && (f.Context.Channel == nil || f.Operation == nil) {
		errs = append(errs, errors.New("a message requires an operation and channel label"))
	}
	if f.Kind == KindAdmission && f.Operation == nil {
		errs = append(errs, errors.New("admission requires an operation"))
	}
	return errors.Join(errs...)
}
