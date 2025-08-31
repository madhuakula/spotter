package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads the configuration from the config file
func LoadConfig() (*SpotterConfig, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	// Check if new config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Try to migrate from legacy .spotter.yaml
		legacyPath, legacyErr := GetLegacyConfigPath()
		if legacyErr == nil {
			if _, legacyStatErr := os.Stat(legacyPath); legacyStatErr == nil {
				// Legacy config exists, migrate it
				if migratedConfig, migrateErr := migrateLegacyConfig(legacyPath, configPath); migrateErr == nil {
					return migratedConfig, nil
				}
				// If migration fails, continue with default config
			}
		}
		// No config file exists, return default config
		return DefaultConfig(), nil
	}

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

// migrateLegacyConfig migrates from legacy .spotter.yaml to new config.yaml
func migrateLegacyConfig(legacyPath, newPath string) (*SpotterConfig, error) {
	// Read legacy config
	legacyData, err := os.ReadFile(legacyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read legacy config: %w", err)
	}

	// Parse legacy config into a generic map first
	var legacyConfig map[string]interface{}
	if err := yaml.Unmarshal(legacyData, &legacyConfig); err != nil {
		return nil, fmt.Errorf("failed to parse legacy config: %w", err)
	}

	// Start with default config
	config := DefaultConfig()

	// Map legacy configuration to new structure
	mapLegacyToNewConfig(legacyConfig, config)

	// Ensure directories exist
	if err := EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	// Save migrated config to new location
	if err := SaveConfig(config); err != nil {
		return nil, fmt.Errorf("failed to save migrated config: %w", err)
	}

	return config, nil
}

// mapLegacyToNewConfig maps legacy configuration values to the new structure
func mapLegacyToNewConfig(legacy map[string]interface{}, config *SpotterConfig) {
	// Map logging configuration
	if logging, ok := legacy["logging"].(map[string]interface{}); ok {
		if level, ok := logging["level"].(string); ok {
			config.Logging.Level = level
		}
		if format, ok := logging["format"].(string); ok {
			config.Logging.Format = format
		}
	}

	// Map scanner configuration
	if scanner, ok := legacy["scanner"].(map[string]interface{}); ok {
		if workers, ok := scanner["workers"].(int); ok {
			config.Scanner.Workers = workers
		}
		if maxConcurrency, ok := scanner["max_concurrency"].(int); ok {
			config.Scanner.MaxConcurrency = maxConcurrency
		}
		if timeout, ok := scanner["timeout"].(string); ok {
			if duration, err := time.ParseDuration(timeout); err == nil {
				config.Scanner.Timeout = duration
			}
		}
		// Map other scanner fields as needed
	}

	// Map output configuration
	if output, ok := legacy["output"].(map[string]interface{}); ok {
		if format, ok := output["format"].(string); ok {
			config.Output.Format = format
		}
		if verbose, ok := output["verbose"].(bool); ok {
			config.Output.Verbose = verbose
		}
	}

	// Map kubernetes configuration
	if kubernetes, ok := legacy["kubernetes"].(map[string]interface{}); ok {
		if kubeconfig, ok := kubernetes["kubeconfig"].(string); ok {
			config.Kubernetes.Kubeconfig = kubeconfig
		}
		if context, ok := kubernetes["context"].(string); ok {
			config.Kubernetes.Context = context
		}
	}

	// Add more mappings as needed for other sections
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

	// Merge scanner config
	if config.Scanner.Workers == 0 {
		config.Scanner.Workers = defaults.Scanner.Workers
	}
	if config.Scanner.MaxConcurrency == 0 {
		config.Scanner.MaxConcurrency = defaults.Scanner.MaxConcurrency
	}
	if config.Scanner.Timeout == 0 {
		config.Scanner.Timeout = defaults.Scanner.Timeout
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

	// Load or create config
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Save default config if it doesn't exist
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := SaveConfig(config); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
	}

	return config, nil
}
