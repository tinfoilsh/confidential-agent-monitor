package store

// Keys is the Monitor's persisted key material, created on first use.
type Keys struct {
	HostKey string `json:"host_key"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}
