package mqtt

type MQTTFacts struct {
	Command string `json:"command"`
	Topic   string `json:"topic"`
	QoS     byte   `json:"qos"`
	Retain  bool   `json:"retain"`
	Payload []byte `json:"payload,omitempty"`
}

type Details struct {
	MQTT *MQTTFacts `json:"mqtt,omitempty"`
}
