package recommendations

import (
	"context"
	"strings"

	"github.com/madhuakula/spotter/pkg/models"
)

// LoadRuleContexts builds a minimal RAG map from embedded builtin rules.
func LoadRuleContexts(ctx context.Context, rules []*models.SpotterRule) (map[string]RuleContext, error) {
	m := make(map[string]RuleContext, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		ctx := RuleContext{
			ID:          r.GetID(),
			Name:        r.Metadata.Name,
			Category:    r.Metadata.Labels["category"],
			Description: truncate(r.Metadata.Annotations["rules.spotter.dev/description"], 600),
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
