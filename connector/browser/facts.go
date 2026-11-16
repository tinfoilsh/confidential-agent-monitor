package browser

type BrowserFacts struct {
	Command string   `json:"command"`
	URL     string   `json:"url"`
	Host    string   `json:"host"`
	Text    string   `json:"text,omitempty"`
	Secrets []string `json:"secrets,omitempty"`
	// Logins is whether the session held saved logins; without them it sees only the public web.
	Logins bool `json:"logins"`
}

type Details struct {
	Browser *BrowserFacts `json:"browser,omitempty"`
}
