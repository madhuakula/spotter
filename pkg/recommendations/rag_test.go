package recommendations

import (
	"context"
	"testing"
)

func TestLoadRuleContexts(t *testing.T) {
	ctx := context.Background()
	m, err := LoadRuleContexts(ctx)
	if err != nil {
		t.Fatalf("LoadRuleContexts error: %v", err)
	}
	if len(m) == 0 {
		t.Fatalf("expected some builtin rules, got 0")
	}
}
