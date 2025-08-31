package cmd

import (
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long: `Configuration management commands for Spotter.

This command provides subcommands for managing Spotter configuration:
- init: Initialize a new configuration file
- validate: Validate existing configuration
- show: Display current configuration

Examples:
  # Initialize a new configuration file
  spotter config init
  
  # Initialize with force overwrite
  spotter config init --force
  
  # Validate current configuration
  spotter config validate
  
  # Show current configuration
  spotter config show`,
}

func init() {
	// Add config command to root
	rootCmd.AddCommand(configCmd)
}