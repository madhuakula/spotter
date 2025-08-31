package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads the configuration from the config file
func LoadConfig(configPath string) (*SpotterConfig, error) {
	// Try to load the config file if specified
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			return loadConfigFromFile(configPath)
		}
	}

	// If no config file found, return default config
	return DefaultConfig(), nil
}

// loadConfigFromFile loads configuration from a specific file
func loadConfigFromFile(configPath string) (*SpotterConfig, error) {
	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var config SpotterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Fill in missing fields with defaults
	defaultConfig := DefaultConfig()
	mergeWithDefaults(&config, defaultConfig)

	return &config, nil
}





// mergeWithDefaults fills in missing fields with default values
func mergeWithDefaults(config *SpotterConfig, defaults *SpotterConfig) {
	// Legacy fields
	if config.HubURL == "" {
		config.HubURL = defaults.HubURL
	}
	if config.CacheDir == "" {
		config.CacheDir = defaults.CacheDir
	}
	if config.RulesDir == "" {
		config.RulesDir = defaults.RulesDir
	}
	if config.PacksDir == "" {
		config.PacksDir = defaults.PacksDir
	}

	// Merge logging config
	if config.Logging.Level == "" {
		config.Logging.Level = defaults.Logging.Level
	}
	if config.Logging.Format == "" {
		config.Logging.Format = defaults.Logging.Format
	}

	// Merge output config
	if config.Output.Format == "" {
		config.Output.Format = defaults.Output.Format
	}

	// Merge kubernetes config
	if config.Kubernetes.Kubeconfig == "" {
		config.Kubernetes.Kubeconfig = defaults.Kubernetes.Kubeconfig
	}
	if config.Kubernetes.Timeout == 0 {
		config.Kubernetes.Timeout = defaults.Kubernetes.Timeout
	}

	// Add more merging logic as needed
}

// SaveConfig saves the configuration to the config file
func SaveConfig(config *SpotterConfig) error {
	// Ensure directories exist
	if err := EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	configPath, err := GetConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// InitializeConfig initializes the configuration and creates necessary directories
func InitializeConfig() (*SpotterConfig, error) {
	// Ensure directories exist
	if err := EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	// Get config path
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	// Load or create config
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Save default config if it doesn't exist

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := SaveConfig(config); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
	}

	return config, nil
}
