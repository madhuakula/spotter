package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/models"
	"gopkg.in/yaml.v3"
)

// Client represents a hub client
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	config     *config.SpotterConfig
}

// NewClient creates a new hub client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiKey: apiKey,
	}
}

// NewClientWithConfig creates a new hub client with configuration
func NewClientWithConfig(cfg *config.SpotterConfig) *Client {
	return &Client{
		baseURL: cfg.HubURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiKey: cfg.APIKey,
		config: cfg,
	}
}

// SearchRequest represents a search request to the hub
type SearchRequest struct {
	Query    string `json:"query"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

// SearchResponse represents the response from a search request
type SearchResponse struct {
	Rules      []RuleInfo `json:"rules"`
	TotalCount int        `json:"total_count"`
	Limit      int        `json:"limit"`
	Offset     int        `json:"offset"`
}

// RuleInfo represents basic information about a rule
type RuleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
	Author      string   `json:"author"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// RulePackInfo represents information about a rule pack
type RulePackInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Rules       []string `json:"rules"`
	Author      string   `json:"author"`
}

// SearchRules searches for rules in the hub
func (c *Client) SearchRules(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	// Get all rules from the API
	endpoint := "/rules.json"
	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var allRulesResp struct {
		Rules []RuleInfo `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&allRulesResp); err != nil {
		return nil, fmt.Errorf("failed to decode rules response: %w", err)
	}

	// Filter rules based on search criteria
	var filteredRules []RuleInfo
	for _, rule := range allRulesResp.Rules {
		// Apply filters
		if req.Category != "" && rule.Category != req.Category {
			continue
		}
		if req.Severity != "" && rule.Severity != req.Severity {
			continue
		}
		if req.Query != "" {
			// Simple text search in title
			query := strings.ToLower(req.Query)
			if !strings.Contains(strings.ToLower(rule.Title), query) {
				continue
			}
		}
		filteredRules = append(filteredRules, rule)
	}

	return &SearchResponse{
		Rules:      filteredRules,
		TotalCount: len(filteredRules),
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetRule retrieves a specific rule by ID
func (c *Client) GetRule(ctx context.Context, ruleID string) (*models.SpotterRule, error) {
	// First get all rules to find the category for this rule
	endpoint := "/rules.json"
	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules list: %w", err)
	}
	defer resp.Body.Close()

	var allRulesResp struct {
		Rules []RuleInfo `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&allRulesResp); err != nil {
		return nil, fmt.Errorf("failed to decode rules response: %w", err)
	}

	// Find the rule to get its category
	var targetRule *RuleInfo
	for _, rule := range allRulesResp.Rules {
		if rule.ID == ruleID {
			targetRule = &rule
			break
		}
	}
	if targetRule == nil {
		return nil, fmt.Errorf("rule %s not found", ruleID)
	}

	// Get the specific rule using the category and ID
	ruleEndpoint := "/rules/" + url.PathEscape(targetRule.Category) + "/" + url.PathEscape(ruleID) + "/" + url.PathEscape(ruleID) + ".json"
	ruleResp, err := c.makeRequest(ctx, "GET", ruleEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}
	defer ruleResp.Body.Close()

	// Parse the API response which contains the rule in a "raw_rule" field
	var apiResp struct {
		RawRule models.SpotterRule `json:"raw_rule"`
	}
	if err := json.NewDecoder(ruleResp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode rule response: %w", err)
	}

	return &apiResp.RawRule, nil
}

// GetRulePack retrieves a rule pack by name
func (c *Client) GetRulePack(ctx context.Context, packName string) (*RulePackInfo, error) {
	// Use the correct API endpoint format for rule packs
	endpoint := "rulepacks/" + url.PathEscape(packName) + "/" + url.PathEscape(packName) + ".json"
	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule pack: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var pack RulePackInfo
	if err := json.NewDecoder(resp.Body).Decode(&pack); err != nil {
		return nil, fmt.Errorf("failed to decode rule pack: %w", err)
	}

	return &pack, nil
}

// SaveRuleToCache saves a rule to the local cache
func (c *Client) SaveRuleToCache(rule *models.SpotterRule) error {
	if c.config == nil {
		return fmt.Errorf("no configuration available for caching")
	}
	
	// Ensure rules directory exists
	if err := os.MkdirAll(c.config.RulesDir, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}
	
	// Create file path
	filename := fmt.Sprintf("%s.yaml", rule.GetID())
	filePath := filepath.Join(c.config.RulesDir, filename)
	
	// Marshal rule to YAML
	data, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %w", err)
	}
	
	return nil
}

// SaveRulePackToCache saves a rule pack to the local cache
func (c *Client) SaveRulePackToCache(pack *RulePackInfo) error {
	if c.config == nil {
		return fmt.Errorf("no configuration available for caching")
	}
	
	// Create pack directory
	packDir := filepath.Join(c.config.PacksDir, pack.ID)
	if err := os.MkdirAll(packDir, 0755); err != nil {
		return fmt.Errorf("failed to create pack directory: %w", err)
	}
	
	// Save pack metadata
	packFile := filepath.Join(packDir, "pack.yaml")
	data, err := yaml.Marshal(pack)
	if err != nil {
		return fmt.Errorf("failed to marshal pack: %w", err)
	}
	
	if err := os.WriteFile(packFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write pack file: %w", err)
	}
	
	return nil
}

// GetRuleFromCache retrieves a rule from the local cache
func (c *Client) GetRuleFromCache(ruleID string) (*models.SpotterRule, error) {
	if c.config == nil {
		return nil, fmt.Errorf("no configuration available for caching")
	}
	
	filename := fmt.Sprintf("%s.yaml", ruleID)
	filePath := filepath.Join(c.config.RulesDir, filename)
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("rule not found in cache: %s", ruleID)
	}
	
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cached rule: %w", err)
	}
	
	// Unmarshal YAML
	var rule models.SpotterRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached rule: %w", err)
	}
	
	return &rule, nil
}

// GetRulePackFromCache retrieves a rule pack from the local cache
func (c *Client) GetRulePackFromCache(packID string) (*RulePackInfo, error) {
	if c.config == nil {
		return nil, fmt.Errorf("no configuration available for caching")
	}
	
	packFile := filepath.Join(c.config.PacksDir, packID, "pack.yaml")
	
	// Check if file exists
	if _, err := os.Stat(packFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("rule pack not found in cache: %s", packID)
	}
	
	// Read file
	data, err := os.ReadFile(packFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cached rule pack: %w", err)
	}
	
	// Unmarshal YAML
	var pack RulePackInfo
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached rule pack: %w", err)
	}
	
	return &pack, nil
}

// makeRequest makes an HTTP request to the hub API
func (c *Client) makeRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Response, error) {
	url, err := url.JoinPath(c.baseURL, endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "spotter-cli/1.0.0")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}