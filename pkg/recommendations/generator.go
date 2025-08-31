package recommendations

import (
	"context"
	"fmt"
	"time"

	"github.com/madhuakula/spotter/pkg/models"
)

// GenerateRecommendations is the main entrypoint.
func GenerateRecommendations(ctx context.Context, scan models.ScanResult, params Params) (Output, error) {
	if params.TopN <= 0 {
		params.TopN = 5
	}
	if params.Host == "" {
		params.Host = "http://localhost:11434"
	}
	if params.Timeout == 0 {
		params.Timeout = 8 * time.Second
	}

	risk, scored := ScoreScan(scan)
	if len(scored) == 0 {
		return Output{RiskScore: 0, Recommendations: nil}, nil
	}
	if len(scored) > params.TopN {
		scored = scored[:params.TopN]
	}

	rag, err := LoadRuleContexts(ctx, params.Rules)
	if err != nil {
		return Output{}, err
	}
	prompt, err := BuildPrompt(risk, params.TopN, scored, rag)
	if err != nil {
		return Output{}, err
	}

	var recs []Recommendation
	switch params.Provider {
	case "", "ollama":
		recs, err = CallOllama(ctx, params.Host, params.Model, prompt, params.Timeout)
	default:
		// Unsupported provider
		return Output{}, fmt.Errorf("provider %s not supported", params.Provider)
	}

	// If LLM call fails, return output with error message instead of failing completely
	if err != nil {
		return Output{
			RiskScore:       risk,
			Recommendations: nil,
			Error:           fmt.Sprintf("AI model unavailable: %v", err),
		}, nil
	}

	// If LLM returns empty recommendations, return empty output
	if len(recs) == 0 {
		return Output{
			RiskScore:       risk,
			Recommendations: nil,
			Error:           "AI model returned no recommendations",
		}, nil
	}

	// assign priorities 1..N if not set
	for i := range recs {
		recs[i].Priority = i + 1
	}
	return Output{
		RiskScore:       risk,
		Recommendations: recs,
	}, nil
}
