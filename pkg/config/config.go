package config

import (
	"os"
	"path/filepath"
)

// SpotterConfig represents the Spotter configuration
type SpotterConfig struct {
	HubURL   string `yaml:"hub_url" json:"hub_url"`
	APIKey   string `yaml:"api_key" json:"api_key"`
	CacheDir string `yaml:"cache_dir" json:"cache_dir"`
	RulesDir string `yaml:"rules_dir" json:"rules_dir"`
	PacksDir string `yaml:"packs_dir" json:"packs_dir"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *SpotterConfig {
	homeDir, _ := os.UserHomeDir()
	spotterDir := filepath.Join(homeDir, ".spotter")

	return &SpotterConfig{
		HubURL:   "https://rules.spotter.run/api/v1",
		APIKey:   "",
		CacheDir: spotterDir,
		RulesDir: filepath.Join(spotterDir, "rules"),
		PacksDir: filepath.Join(spotterDir, "rulepacks"),
	}
}

// GetSpotterDir returns the Spotter configuration directory
func GetSpotterDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".spotter"), nil
}

// GetConfigPath returns the path to the configuration file
func GetConfigPath() (string, error) {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(spotterDir, "config.yaml"), nil
}

// GetRulesDir returns the rules directory path
func GetRulesDir() (string, error) {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(spotterDir, "rules"), nil
}

// GetRulePacksDir returns the rule packs directory path
func GetRulePacksDir() (string, error) {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(spotterDir, "rulepacks"), nil
}

// EnsureDirectories creates the necessary directories if they don't exist
func EnsureDirectories() error {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return err
	}

	// Create main .spotter directory
	if err := os.MkdirAll(spotterDir, 0755); err != nil {
		return err
	}

	// Create rules directory
	rulesDir, err := GetRulesDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return err
	}

	// Create rule packs directory
	packsDir, err := GetRulePacksDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return err
	}

	return nil
}
