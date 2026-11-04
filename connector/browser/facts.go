package browser

type BrowserFacts struct {
	Command string   `json:"command"`
	URL     string   `json:"url"`
	Host    string   `json:"host"`
	Text    string   `json:"text,omitempty"`
	Secrets []string `json:"secrets,omitempty"`
}

type Details struct {
	Browser *BrowserFacts `json:"browser,omitempty"`
}
