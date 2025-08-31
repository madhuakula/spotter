package recommendations

import (
	"time"
)

// Params configures recommendation generation.
type Params struct {
	TopN     int
	Model    string
	Host     string
	Timeout  time.Duration
	Provider string // "ollama" | "openai" | "gemini" (future)
	APIKey   string // for providers requiring auth
}

// Output is the result of recommendation generation.
type Output struct {
	RiskScore       float64          `json:"riskScore"`
	Recommendations []Recommendation `json:"recommendations"`
	Error           string           `json:"error,omitempty"`
}

// Recommendation is a single recommended action.
type Recommendation struct {
	Title        string   `json:"title"`
	Priority     int      `json:"priority"`
	Rationale    string   `json:"rationale"`
	Actions      []string `json:"actions"`
	RelatedRules []string `json:"related_rules"`
}

// RuleContext contains short, grounded information for a rule.
type RuleContext struct {
	ID          string
	Name        string
	Category    string
	Description string
	Remediation string
}
