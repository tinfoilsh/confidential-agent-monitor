package format

// The states a request record moves through, as the audit log stores them.
const (
	RecordPending  = "pending"
	RecordExpired  = "expired"
	RecordOutdated = "outdated"
	RecordAllowed  = "allowed"
	RecordRefused  = "refused"
	RecordDenied   = "denied"
	RecordRevoked  = "revoked"
)

// Why a request was refused, as its record stores it.
type Cause string

const (
	CauseInvalid      Cause = "invalid"
	CausePrecondition Cause = "precondition"
	CauseDenied       Cause = "denied"
	CauseRejected     Cause = "rejected"
	CauseExpired      Cause = "expired"
)

type Refusal struct {
	Cause   Cause    `json:"cause"`
	Reasons []string `json:"reasons,omitempty"`
}
