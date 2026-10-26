package nats

type NATSFacts struct {
	Command string              `json:"command"`
	Subject string              `json:"subject"`
	Reply   string              `json:"reply,omitempty"`
	Queue   string              `json:"queue,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Payload []byte              `json:"payload,omitempty"`
}

type Details struct {
	NATS *NATSFacts `json:"nats,omitempty"`
}
