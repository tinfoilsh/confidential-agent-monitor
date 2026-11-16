package facts

import (
	"encoding/json"
	"errors"
)

// Event owns one captured protocol operation. Worker transport carries these
// exact bytes; trusted identity and current policy state are added only at Gate.
type Event string

type event struct {
	Observation
	Invalid string `json:"invalid,omitempty"`
}

func Capture(o Observation, invalid error) Event {
	in := event{Observation: o}
	if invalid != nil {
		in.Invalid = invalid.Error()
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return Event(`{"invalid":"invalid captured facts"}`)
	}
	return Event(raw)
}

// Decode returns the observation; an invalid capture also returns its reason.
func (e Event) Decode() (Observation, error) {
	var in event
	if err := DecodeNumbers([]byte(e), &in); err != nil {
		return Observation{}, err
	}
	if in.Invalid != "" {
		return in.Observation, errors.New(in.Invalid)
	}
	return in.Observation, nil
}
