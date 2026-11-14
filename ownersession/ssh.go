package ownersession

const (
	SSHChannel           = "tinfoil-owner-http-v1"
	SSHGenerationRequest = "tinfoil-owner-generation-v1"
	// SessionHeader carries SSHOptions.Token on each API request over the channel.
	SessionHeader = "X-Tinfoil-Session"
)

// SSHOptions is the extra data of an SSHChannel, in SSH wire encoding. The authenticated owner CLI supplies it, never the browser.
type SSHOptions struct {
	Host       string
	Token      string
	Generation uint64
}

// SSHGeneration is the payload of an SSHGenerationRequest, in SSH wire encoding.
type SSHGeneration struct{ Generation uint64 }
