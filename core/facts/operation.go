package facts

// OperationSummary is protocol-neutral catalog metadata, never an authorization input.
type OperationSummary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}
