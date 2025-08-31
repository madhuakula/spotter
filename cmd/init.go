package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	pkgconfig "github.com/madhuakula/spotter/pkg/config"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a ~/.spotter/config.yaml configuration file",
	Long: `Initialize a ~/.spotter/config.yaml configuration file with sane defaults and documented options.

This command creates a comprehensive configuration file that includes:
- All available configuration options with documentation
- Sane default values for immediate use
- Comments explaining each configuration section

The configuration file will be created in ~/.spotter/config.yaml
unless a different path is specified with the --config flag.

Examples:
  # Create ~/.spotter/config.yaml
  spotter init
  
  # Create configuration file at specific path
  spotter init --config /path/to/my-config.yaml
  
  # Force overwrite existing configuration
  spotter init --force`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInit(cmd)
	},
}

func init() {
	// Add init command to root
	rootCmd.AddCommand(initCmd)

	// Add flags specific to init command
	initCmd.Flags().Bool("force", false, "force overwrite existing configuration file")
}

func runInit(cmd *cobra.Command) error {
	// Get configuration file path
	configPath := cfgFile
	if configPath == "" {
		// Use the default config path from pkg/config
		defaultPath, err := pkgconfig.GetConfigPath()
		if err != nil {
			return fmt.Errorf("failed to get default config path: %w", err)
		}
		configPath = defaultPath
	}

	// Check if file already exists
	if _, err := os.Stat(configPath); err == nil {
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			return fmt.Errorf("configuration file already exists at %s. Use --force to overwrite", configPath)
		}
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Write the configuration file
	if err := writeDefaultConfig(configPath); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	fmt.Printf("Configuration file created successfully at: %s\n", configPath)
	fmt.Println("\nYou can now customize the configuration according to your needs.")
	fmt.Println("Run 'spotter scan --help' to see how to use the configuration file.")

	return nil
}

func writeDefaultConfig(path string) error {
	// Create default config using the consolidated structure
	defaultConfig := pkgconfig.DefaultConfig()
	
	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Save the config using the existing SaveConfig function
	if err := pkgconfig.SaveConfig(defaultConfig); err != nil {
		return fmt.Errorf("failed to save default config: %w", err)
	}
	
	return nil

}
