package recommendations

import (
	"testing"

	"github.com/madhuakula/spotter/pkg/models"
)

func TestScoreScanBasic(t *testing.T) {
	scan := models.ScanResult{
		Results: []models.ValidationResult{
			{RuleID: "R1", Passed: false, Severity: models.SeverityHigh, Category: "Access Control", Resource: map[string]interface{}{"kind": "Role", "metadata": map[string]interface{}{"namespace": "ns1"}}},
			{RuleID: "R1", Passed: false, Severity: models.SeverityHigh, Category: "Access Control", Resource: map[string]interface{}{"kind": "Role", "metadata": map[string]interface{}{"namespace": "ns2"}}},
			{RuleID: "R2", Passed: false, Severity: models.SeverityLow, Category: "Configuration & Resource Hygiene", Resource: map[string]interface{}{"kind": "ConfigMap", "metadata": map[string]interface{}{"namespace": "ns1"}}},
		},
	}

	risk, scored := ScoreScan(scan)
	if risk <= 0 {
		t.Fatalf("expected positive risk, got %f", risk)
	}
	if len(scored) != 2 {
		t.Fatalf("expected 2 scored rules, got %d", len(scored))
	}
	if scored[0].RuleID != "R1" {
		t.Fatalf("expected R1 to rank first, got %s", scored[0].RuleID)
	}
}
