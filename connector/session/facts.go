package session

type SSHFacts struct {
	Request   string       `json:"request"`
	Command   string       `json:"command,omitempty"`
	Subsystem string       `json:"subsystem,omitempty"`
	Term      string       `json:"term,omitempty"`
	Env       *SSHEnvFacts `json:"env,omitempty"`
}

type SSHEnvFacts struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CommandFacts struct {
	Argv []string `json:"argv"`
}

type GitFacts struct {
	Type       string   `json:"type"`
	Tree       string   `json:"tree,omitempty"`
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"`
	Tag        string   `json:"tag,omitempty"`
	Parents    []string `json:"parents"`
	Author     string   `json:"author,omitempty"`
	Committer  string   `json:"committer,omitempty"`
	Tagger     string   `json:"tagger,omitempty"`
	Message    string   `json:"message"`
}

type SFTPFacts struct {
	Command    string            `json:"command"`
	Path       string            `json:"path"`
	Target     string            `json:"target,omitempty"`
	Read       bool              `json:"read,omitempty"`
	Write      bool              `json:"write,omitempty"`
	Flags      uint32            `json:"flags,omitempty"`
	Offset     uint64            `json:"offset,omitempty"`
	Size       uint32            `json:"size,omitempty"`
	Attributes map[string]uint64 `json:"attributes,omitempty"`
}

type Details struct {
	SSH     *SSHFacts     `json:"ssh,omitempty"`
	Command *CommandFacts `json:"command,omitempty"`
	Payload *GitFacts     `json:"payload,omitempty"`
	SFTP    *SFTPFacts    `json:"sftp,omitempty"`
}
