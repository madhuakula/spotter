package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/hub"
	"github.com/madhuakula/spotter/pkg/models"
)

// CacheManager handles local caching of rules and rule packs
type CacheManager struct {
	config *config.SpotterConfig
}

// NewCacheManager creates a new cache manager
func NewCacheManager(cfg *config.SpotterConfig) *CacheManager {
	return &CacheManager{
		config: cfg,
	}
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	CachedAt    time.Time `json:"cached_at"`
	LastUpdated time.Time `json:"last_updated"`
	FilePath    string    `json:"file_path"`
	Type        string    `json:"type"` // "rule" or "pack"
}

// CacheIndex maintains an index of all cached items
type CacheIndex struct {
	Entries map[string]CacheEntry `json:"entries"`
	Version string                `json:"version"`
}

// SaveRule saves a rule to the local cache
func (cm *CacheManager) SaveRule(rule *models.SpotterRule) error {
	if err := config.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	// Create rule file path
	ruleFile := filepath.Join(cm.config.RulesDir, fmt.Sprintf("%s.yaml", rule.GetID()))

	// Save rule to file
	ruleData, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	if err := os.WriteFile(ruleFile, ruleData, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %w", err)
	}

	// Update cache index
	return cm.updateIndex(rule.GetID(), rule.GetVersion(), ruleFile, "rule")
}

// SaveRulePack saves a rule pack to the local cache
func (cm *CacheManager) SaveRulePack(pack *hub.RulePackInfo) error {
	if err := config.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	// Create pack file path
	packFile := filepath.Join(cm.config.PacksDir, fmt.Sprintf("%s.yaml", pack.ID))

	// Save pack to file
	packData, err := yaml.Marshal(pack)
	if err != nil {
		return fmt.Errorf("failed to marshal pack: %w", err)
	}

	if err := os.WriteFile(packFile, packData, 0644); err != nil {
		return fmt.Errorf("failed to write pack file: %w", err)
	}

	// Update cache index
	return cm.updateIndex(pack.ID, pack.Version, packFile, "pack")
}

// GetRule retrieves a rule from the local cache
func (cm *CacheManager) GetRule(ruleID string) (*models.SpotterRule, error) {
	ruleFile := filepath.Join(cm.config.RulesDir, fmt.Sprintf("%s.yaml", ruleID))

	if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("rule %s not found in cache", ruleID)
	}

	ruleData, err := os.ReadFile(ruleFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file: %w", err)
	}

	var rule models.SpotterRule
	if err := yaml.Unmarshal(ruleData, &rule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule: %w", err)
	}

	return &rule, nil
}

// GetRulePack retrieves a rule pack from the local cache
func (cm *CacheManager) GetRulePack(packID string) (*hub.RulePackInfo, error) {
	packFile := filepath.Join(cm.config.PacksDir, fmt.Sprintf("%s.yaml", packID))

	if _, err := os.Stat(packFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("pack %s not found in cache", packID)
	}

	packData, err := os.ReadFile(packFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read pack file: %w", err)
	}

	var pack hub.RulePackInfo
	if err := yaml.Unmarshal(packData, &pack); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pack: %w", err)
	}

	return &pack, nil
}

// ListCachedRules returns a list of all cached rules
func (cm *CacheManager) ListCachedRules() ([]CacheEntry, error) {
	index, err := cm.loadIndex()
	if err != nil {
		return nil, err
	}

	var rules []CacheEntry
	for _, entry := range index.Entries {
		if entry.Type == "rule" {
			rules = append(rules, entry)
		}
	}

	return rules, nil
}

// ListCachedPacks returns a list of all cached rule packs
func (cm *CacheManager) ListCachedPacks() ([]CacheEntry, error) {
	index, err := cm.loadIndex()
	if err != nil {
		return nil, err
	}

	var packs []CacheEntry
	for _, entry := range index.Entries {
		if entry.Type == "pack" {
			packs = append(packs, entry)
		}
	}

	return packs, nil
}

// IsRuleCached checks if a rule is cached locally
func (cm *CacheManager) IsRuleCached(ruleID string) bool {
	ruleFile := filepath.Join(cm.config.RulesDir, fmt.Sprintf("%s.yaml", ruleID))
	_, err := os.Stat(ruleFile)
	return err == nil
}

// IsPackCached checks if a pack is cached locally
func (cm *CacheManager) IsPackCached(packID string) bool {
	packFile := filepath.Join(cm.config.PacksDir, fmt.Sprintf("%s.yaml", packID))
	_, err := os.Stat(packFile)
	return err == nil
}

// ClearCache removes all cached items
func (cm *CacheManager) ClearCache() error {
	if err := os.RemoveAll(cm.config.RulesDir); err != nil {
		return fmt.Errorf("failed to clear rules cache: %w", err)
	}

	if err := os.RemoveAll(cm.config.PacksDir); err != nil {
		return fmt.Errorf("failed to clear packs cache: %w", err)
	}

	// Remove index file
	indexFile := filepath.Join(cm.config.CacheDir, "index.json")
	if err := os.Remove(indexFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove index file: %w", err)
	}

	return config.EnsureDirectories()
}

// updateIndex updates the cache index with a new entry
func (cm *CacheManager) updateIndex(id, version, filePath, itemType string) error {
	index, err := cm.loadIndex()
	if err != nil {
		// Create new index if it doesn't exist
		index = &CacheIndex{
			Entries: make(map[string]CacheEntry),
			Version: "1.0",
		}
	}

	entry := CacheEntry{
		ID:          id,
		Version:     version,
		CachedAt:    time.Now(),
		LastUpdated: time.Now(),
		FilePath:    filePath,
		Type:        itemType,
	}

	index.Entries[id] = entry

	return cm.saveIndex(index)
}

// loadIndex loads the cache index from disk
func (cm *CacheManager) loadIndex() (*CacheIndex, error) {
	indexFile := filepath.Join(cm.config.CacheDir, "index.json")

	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("index file not found")
	}

	indexData, err := os.ReadFile(indexFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read index file: %w", err)
	}

	var index CacheIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	return &index, nil
}

// saveIndex saves the cache index to disk
func (cm *CacheManager) saveIndex(index *CacheIndex) error {
	indexFile := filepath.Join(cm.config.CacheDir, "index.json")

	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	return os.WriteFile(indexFile, indexData, 0644)
}