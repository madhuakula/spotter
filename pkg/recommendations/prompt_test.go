package recommendations

import "testing"

func TestBuildPrompt(t *testing.T) {
	top := []ScoredRule{{RuleID: "R1", Severity: "HIGH", Category: "Access Control", Count: 3, Namespaces: 2, Kinds: 1, Score: 7.1}}
	rag := map[string]RuleContext{"R1": {ID: "R1", Name: "Test", Category: "Access Control", Description: "desc", Remediation: "fix"}}
	_, err := BuildPrompt(42.0, 1, top, rag)
	if err != nil {
		t.Fatalf("BuildPrompt error: %v", err)
	}
}
