package llmpool

import (
	"context"
	"github.com/Autumn-27/norma/llm"
	"testing"
)

func TestCloudBackupGetsToolOutputBudgetWithoutChangingQwen(t *testing.T) {
	local := &Member{ID: 1, Name: "Qwen", NoTools: true, MaxRequestBytes: 12288}
	cloud := &Member{ID: 2, Name: "OpenAI", NoTools: false}
	pool := New([]*Member{local, cloud}, nil)
	input := llm.CompletionRequest{MaxTokens: 256, Tools: []llm.ToolSchema{{Name: "Write"}}}
	if got := pool.requestForMember(input, local).MaxTokens; got != 256 {
		t.Fatalf("local cap changed to %d", got)
	}
	if got := pool.requestForMember(input, cloud).MaxTokens; got != 3072 {
		t.Fatalf("cloud tool cap %d, want 3072", got)
	}
	if got := pool.requestForMember(llm.CompletionRequest{MaxTokens: 256}, cloud).MaxTokens; got != 256 {
		t.Fatalf("plain text cap changed to %d", got)
	}
	if got := pool.requestForMember(llm.CompletionRequest{MaxTokens: 4096, Tools: input.Tools}, cloud).MaxTokens; got != 4096 {
		t.Fatalf("explicit high cap changed to %d", got)
	}
	cloudOnly := New([]*Member{cloud}, nil)
	if got := cloudOnly.requestForMember(input, cloud).MaxTokens; got != 256 {
		t.Fatalf("unrelated profile cap changed to %d", got)
	}
}

func TestUnavailableCloudBackupDoesNotSendToolCallsToQwen(t *testing.T) {
	local := &Member{ID: 1, Name: "Qwen", NoTools: true, MaxRequestBytes: 12288, Prov: okProv("qwen", "should_not_be_called")}
	pool := New([]*Member{local}, nil)
	req := llm.CompletionRequest{MaxTokens: 256, Tools: []llm.ToolSchema{{Name: "Write"}}}
	if !requestHasNoToolCapableMember(req, pool.order(req)) {
		t.Fatal("must detect no tool-capable member")
	}
	_, err := drain(pool.Stream(context.Background(), req))
	if err == nil {
		t.Fatal("tool request must not be sent to local Qwen")
	}
	if local.Prov.(*fakeProv).calls != 0 {
		t.Fatal("local Qwen was incorrectly invoked for tool request")
	}
	if _, _, _, err = pool.Complete(context.Background(), req); err == nil {
		t.Fatal("non-streaming must fail closed too")
	}
}
