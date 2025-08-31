package recommendations

import (
	"context"
	"fmt"
	"strings"

	"github.com/madhuakula/spotter/internal"
	"github.com/madhuakula/spotter/pkg/parser"
)

// LoadRuleContexts builds a minimal RAG map from embedded builtin rules.
func LoadRuleContexts(ctx context.Context) (map[string]RuleContext, error) {
	fsys := internal.GetBuiltinRulesFS()
	p := parser.NewYAMLParser(true)
	rules, err := p.ParseRulesFromFS(ctx, fsys, "builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse builtin rules: %w", err)
	}
	m := make(map[string]RuleContext, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		ctx := RuleContext{
			ID:          r.Spec.ID,
			Name:        r.Spec.Name,
			Category:    r.Spec.Category,
			Description: truncate(r.Spec.Description, 600),
			Remediation: "",
		}
		if r.Spec.Remediation != nil {
			ctx.Remediation = truncate(r.Spec.Remediation.Manual, 600)
		}
		m[ctx.ID] = ctx
	}
	return m, nil
}

func truncate(s string, limit int) string {
	if s == "" || limit <= 0 {
		return s
	}
	if len(s) <= limit {
		return s
	}
	// naive word-safe truncation
	cut := s[:limit]
	if i := strings.LastIndex(cut, " "); i > 0 {
		cut = cut[:i]
	}
	return cut + "…"
}
