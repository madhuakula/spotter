package recommendations

import (
	"encoding/json"
	"fmt"
)

type promptPayload struct {
	RiskScore float64       `json:"risk_score"`
	TopN      int           `json:"top_n"`
	Issues    []issueBrief  `json:"issues"`
	Rules     []RuleContext `json:"rules"`
}

type issueBrief struct {
	RuleID     string  `json:"rule_id"`
	Severity   string  `json:"severity"`
	Category   string  `json:"category"`
	Count      int     `json:"count"`
	Namespaces int     `json:"namespaces"`
	Kinds      int     `json:"kinds"`
	Score      float64 `json:"score"`
}

func BuildPrompt(risk float64, topN int, top []ScoredRule, rag map[string]RuleContext) (string, error) {
	var issues []issueBrief
	for _, s := range top {
		issues = append(issues, issueBrief{
			RuleID:     s.RuleID,
			Severity:   string(s.Severity),
			Category:   s.Category,
			Count:      s.Count,
			Namespaces: s.Namespaces,
			Kinds:      s.Kinds,
			Score:      s.Score,
		})
	}
	var rules []RuleContext
	for _, s := range top {
		if rc, ok := rag[s.RuleID]; ok {
			rules = append(rules, rc)
		}
	}
	p := promptPayload{RiskScore: risk, TopN: topN, Issues: issues, Rules: rules}
	jb, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sys := "You are a Kubernetes security consultant. Use ONLY provided JSON. Prioritize risk reduction. Output strict JSON: {\"recommendations\":[{\"title\",\"priority\",\"rationale\",\"actions\",\"related_rules\"}]}"
	return fmt.Sprintf("<SYSTEM>%s</SYSTEM>\n<USER>%s</USER>", sys, string(jb)), nil
}
