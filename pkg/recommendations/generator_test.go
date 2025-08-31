package recommendations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/madhuakula/spotter/pkg/models"
)

func TestGenerateRecommendations_Fallback(t *testing.T) {
	// mock Ollama returning malformed JSON to trigger fallback
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response":"{not-json}"}`))
	}))
	defer ts.Close()

	scan := models.ScanResult{Results: []models.ValidationResult{{RuleID: "R1", Passed: false, Severity: models.SeverityHigh, Category: "Access Control", Resource: map[string]interface{}{"kind": "Role", "metadata": map[string]interface{}{"namespace": "ns1"}}}}}
	out, err := GenerateRecommendations(context.Background(), scan, Params{TopN: 1, Model: "llama3.1:8b", Host: ts.URL})
	if err != nil {
		t.Fatalf("GenerateRecommendations error: %v", err)
	}
	if len(out.Recommendations) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(out.Recommendations))
	}
}
