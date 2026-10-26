package postgres

type PostgresFacts struct {
	SQL string `json:"sql"`
}

type Details struct {
	Postgres *PostgresFacts `json:"postgres,omitempty"`
}
