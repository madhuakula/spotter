package recommendations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type ollamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Format  string                 `json:"format"`
	Options map[string]interface{} `json:"options,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

// CallOllama sends prompt and expects JSON body matching Output.Recommendations schema.
func CallOllama(ctx context.Context, host, model, prompt string, timeout time.Duration) ([]Recommendation, error) {
	reqBody := ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
		Options: map[string]interface{}{
			"temperature": 0.2,
		},
	}
	b, _ := json.Marshal(reqBody)
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("%s/api/generate", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var or ollamaResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return nil, fmt.Errorf("ollama decode failed: %w", err)
	}
	// Parse with flexible types to handle string/int conversions
	var parsed struct {
		Recommendations []map[string]interface{} `json:"recommendations"`
	}
	if err := json.Unmarshal([]byte(or.Response), &parsed); err != nil {
		return nil, fmt.Errorf("model json parse failed: %w", err)
	}

	// Convert to proper Recommendation structs with type conversions
	var recommendations []Recommendation
	for _, recMap := range parsed.Recommendations {
		rec := Recommendation{}

		if title, ok := recMap["title"].(string); ok {
			rec.Title = title
		}

		// Handle priority as both string and number
		if priority, ok := recMap["priority"].(float64); ok {
			rec.Priority = int(priority)
		} else if priorityStr, ok := recMap["priority"].(string); ok {
			// Try to parse string priority
			if priorityStr == "HIGH" || priorityStr == "high" {
				rec.Priority = 1
			} else if priorityStr == "MEDIUM" || priorityStr == "medium" {
				rec.Priority = 2
			} else if priorityStr == "LOW" || priorityStr == "low" {
				rec.Priority = 3
			} else {
				rec.Priority = 1 // Default to high priority
			}
		}

		if rationale, ok := recMap["rationale"].(string); ok {
			rec.Rationale = rationale
		}

		// Handle actions array
		if actionsInterface, ok := recMap["actions"].([]interface{}); ok {
			for _, action := range actionsInterface {
				if actionStr, ok := action.(string); ok {
					rec.Actions = append(rec.Actions, actionStr)
				}
			}
		}

		// Handle related_rules array
		if rulesInterface, ok := recMap["related_rules"].([]interface{}); ok {
			for _, rule := range rulesInterface {
				if ruleStr, ok := rule.(string); ok {
					rec.RelatedRules = append(rec.RelatedRules, ruleStr)
				}
			}
		}

		recommendations = append(recommendations, rec)
	}

	return recommendations, nil
}
