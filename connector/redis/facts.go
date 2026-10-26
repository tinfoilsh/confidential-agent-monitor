package redis

type RedisFacts struct {
	Command string   `json:"command"`
	Argv    []string `json:"argv"`
}

type Details struct {
	Redis *RedisFacts `json:"redis,omitempty"`
}
