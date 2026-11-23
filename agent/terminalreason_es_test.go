package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/harness"
)

func TestTerminalTextSpanishOversizedModelRequest(t *testing.T) {
	old := OutputLanguage
	OutputLanguage = func() string { return "es" }
	t.Cleanup(func() { OutputLanguage = old })
	summary, detail := terminalText(context.Background(), &harness.Terminal{
		Reason: harness.ReasonPromptTooLong, Err: errors.New("openai: status 413: request_size"), Turns: 1,
	}, &runTrace{startedAt: time.Now()})
	if !strings.Contains(summary, "contexto supera") || !strings.Contains(detail, "OpenAI") ||
		!strings.Contains(detail, "413") || strings.Contains(detail, "终态") || strings.Contains(detail, "에이전트") {
		t.Fatalf("Spanish details missing: summary=%s detail=%s", summary, detail)
	}
}
