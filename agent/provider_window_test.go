package agent

import "testing"

func TestPilotCompactionWindowMatchesRealModelLimits(t *testing.T) {
	cases := []struct {
		model string
		k     int
		want  int
	}{
		{"qwen25-1.5b-local", 4, 32000},
		{"gpt-4o-mini", 0, 96000},
		{"gpt-4o-mini", 64, 64000},
		{"other", 0, 200000},
	}
	for _, tc := range cases {
		c := Config{Model: tc.model, ContextWindowK: tc.k}
		if n := c.CompactionWindow(); n != tc.want {
			t.Errorf("%s/%d: %d want %d", tc.model, tc.k, n, tc.want)
		}
	}
}
