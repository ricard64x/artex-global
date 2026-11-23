package agent

import (
	"github.com/Autumn-27/artex/db"
	"testing"
)

func TestWorkerToolLoopGuardStopsRepeatedMalformedJSON(t *testing.T) {
	g := &toolErrorLoopGuard{}
	fail := db.Activity{Kind: "tool_result", IsError: true, Detail: "Error: invalid tool input: input is not valid JSON: unexpected end of JSON input"}
	for i := 1; i <= 4; i++ {
		stop := g.observe(fail)
		if stop != (i == 4) {
			t.Fatalf("round %d stop=%v", i, stop)
		}
	}
}
func TestWorkerToolLoopGuardResetsOnSuccessOrOtherError(t *testing.T) {
	g := &toolErrorLoopGuard{}
	fail := db.Activity{Kind: "tool_result", IsError: true, Detail: "Error: invalid tool input: input is not valid JSON"}
	g.observe(fail)
	g.observe(fail)
	if g.observe(db.Activity{Kind: "tool_result", IsError: false, Detail: "ok"}) {
		t.Fatal("should never stop on success")
	}
	if g.observe(fail) {
		t.Fatal("success did not reset")
	}
	for i := 0; i < 7; i++ {
		if g.observe(db.Activity{Kind: "tool_result", IsError: true, Detail: "HTTP 503 from target"}) {
			t.Fatal("remote error should not trip local-error guard")
		}
	}
	if g.observe(fail) {
		t.Fatal("unrelated errors did not reset")
	}
}
