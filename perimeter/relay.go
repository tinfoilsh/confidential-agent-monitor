package perimeter

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
)

// relayOwner opens the owner socket of the hello's instance, which the owner then runs its own session over.
func relayOwner(dial func(ctx context.Context, instance string) (*websocket.Conn, error)) sessionMode {
	return func(ctx context.Context, c *ownerSession, hello json.RawMessage) {
		var open struct {
			InstanceID string `json:"instance_id"`
		}
		if json.Unmarshal(hello, &open) != nil {
			c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
			return
		}
		upstream, err := dial(ctx, open.InstanceID)
		if err != nil {
			// The innermost cause fits the close frame's 123-byte reason; dial wrappers add the URL.
			for errors.Unwrap(err) != nil {
				err = errors.Unwrap(err)
			}
			c.Conn.Close(websocket.StatusInternalError, "relay unavailable: "+err.Error())
			return
		}
		upstream.SetReadLimit(noise.MaxMsgLen)
		relay(ctx, c.Conn, upstream)
	}
}

// relay copies whole messages each way until either side ends, passing on its close.
func relay(ctx context.Context, owner, upstream *websocket.Conn) {
	defer owner.CloseNow()
	go func() {
		copyMessages(ctx, upstream, owner)
		upstream.CloseNow()
	}()
	copyMessages(ctx, owner, upstream)
}

func copyMessages(ctx context.Context, dst, src *websocket.Conn) {
	for {
		kind, message, err := src.Read(ctx)
		var closed websocket.CloseError
		if errors.As(err, &closed) {
			dst.Close(closed.Code, closed.Reason)
		}
		if err != nil || dst.Write(ctx, kind, message) != nil {
			return
		}
	}
}
