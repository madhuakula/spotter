package hub

import (
	"context"

	"github.com/madhuakula/spotter/pkg/models"
)

// HubClient defines the interface for interacting with the Spotter Hub
type HubClient interface {
	// SearchRules searches for rules in the hub
	SearchRules(ctx context.Context, req SearchRequest) (*SearchResponse, error)
	
	// GetRule retrieves a specific rule by ID
	GetRule(ctx context.Context, ruleID string) (*models.SpotterRule, error)
	
	// GetRulePack retrieves a rule pack by name
	GetRulePack(ctx context.Context, packName string) (*RulePackInfo, error)
}

// Ensure Client implements HubClient interface
var _ HubClient = (*Client)(nil)