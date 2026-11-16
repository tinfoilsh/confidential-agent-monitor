package approval_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/approval"
)

type record struct {
	id      int
	pending bool
}

func TestPendingRecordsSurviveEvictionAndWaitersWake(t *testing.T) {
	var mu sync.Mutex
	records := approval.NewRecords(&mu, 2, func(r *record) bool { return r.pending })
	waiting := &record{1, true}
	mu.Lock()
	defer mu.Unlock()
	records.Add(waiting)
	records.Add(&record{2, false})
	records.Add(&record{3, false})
	records.Add(&record{4, false})
	var ids []int
	for r := range records.All() {
		ids = append(ids, r.id)
	}
	if !slices.Equal(ids, []int{1, 4}) {
		t.Fatalf("kept %v", ids)
	}

	go func() {
		mu.Lock()
		defer mu.Unlock()
		if r, ok := records.Find(func(r *record) bool { return r.id == 1 }); ok {
			r.pending = false
		}
		records.Notify()
	}()
	if expired := records.Wait(context.Background(), time.Now().Add(time.Minute)); expired || waiting.pending {
		t.Fatal("an answer did not wake its waiter")
	}
	if expired := records.Wait(context.Background(), time.Now().Add(10*time.Millisecond)); !expired {
		t.Fatal("deadline not reported")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if expired := records.Wait(ctx, time.Now().Add(time.Minute)); expired {
		t.Fatal("cancellation reported as expiry")
	}
}
