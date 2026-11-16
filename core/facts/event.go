package facts

import (
	"encoding/json"
	"errors"
)

// Event owns one captured protocol operation. Worker transport carries these
// exact bytes; trusted identity and current policy state are added only at Gate.
type Event string

type event struct {
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	Sends      string         `json:"sends"`
	Observes   Label          `json:"observes"`
	Title      string         `json:"title"`
	Details    any            `json:"details"`
	Scope      map[string]any `json:"scope"`
	Invalid    string         `json:"invalid,omitempty"`
}

func Capture(f Facts, invalid error) Event {
	in := event{Operation: f.Operation, Parameters: f.Parameters, Sends: f.Context.Sends, Observes: f.Context.Observes,
		Title: f.Title, Details: f.Details, Scope: f.Scope}
	if invalid != nil {
		in.Invalid = invalid.Error()
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return Event(`{"invalid":"invalid captured facts"}`)
	}
	return Event(raw)
}

// Facts decodes one private view.
func (e Event) Facts() (Facts, error) {
	var in event
	if err := DecodeNumbers([]byte(e), &in); err != nil {
		return Facts{}, err
	}
	f := Facts{Operation: in.Operation, Parameters: in.Parameters, Context: Context{Sends: in.Sends, Observes: in.Observes},
		Title: in.Title, Details: in.Details, Scope: in.Scope}
	if in.Invalid != "" {
		return f, errors.New(in.Invalid)
	}
	return f, nil
}
