package document_test

import (
	"context"
	"errors"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/document"
)

func TestCommitPublishesOnlyWrittenSnapshots(t *testing.T) {
	var v document.Value[int]
	failed := errors.New("storage failed")
	if err := v.Commit(context.Background(), 1, func(context.Context, int) error { return failed }); !errors.Is(err, failed) || v.Get() != 0 {
		t.Fatalf("failed write published: %d, %v", v.Get(), err)
	}
	written := 0
	if err := v.Commit(context.Background(), 2, func(_ context.Context, next int) error { written = next; return nil }); err != nil || v.Get() != 2 || written != 2 {
		t.Fatalf("write %d published %d, %v", written, v.Get(), err)
	}
}
