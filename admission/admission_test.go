package admission_test

import (
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/admission"
)

func TestRecheckEndsOnlyRejectedLiveItems(t *testing.T) {
	var s admission.Set[string]
	ended := map[string]int{}
	end := func(name string) func() { return func() { ended[name]++ } }
	s.Add("kept", end("kept"))
	s.Add("revoked", end("revoked"))
	remove := s.Add("finished", end("finished"))
	remove()
	s.Recheck(func(name string) bool { return name == "kept" })
	if ended["kept"] != 0 || ended["revoked"] != 1 || ended["finished"] != 0 {
		t.Fatal(ended)
	}
}
