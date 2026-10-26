package email

type SMTPFacts struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

type MailFacts struct {
	From        []string `json:"from"`
	To          []string `json:"to"`
	Cc          []string `json:"cc"`
	Subject     string   `json:"subject"`
	Attachments []string `json:"attachments"`
}

type IMAPFacts struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Mailbox string `json:"mailbox,omitempty"`
}

type Details struct {
	SMTP *SMTPFacts `json:"smtp,omitempty"`
	Mail *MailFacts `json:"mail,omitempty"`
	IMAP *IMAPFacts `json:"imap,omitempty"`
}
