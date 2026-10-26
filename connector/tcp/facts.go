package tcp

type TCPFacts struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

type Details struct {
	TCP *TCPFacts `json:"tcp,omitempty"`
}
