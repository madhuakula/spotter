package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	pkgconfig "github.com/madhuakula/spotter/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	verbose      bool
	logger       *slog.Logger
	globalConfig *pkgconfig.SpotterConfig
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "spotter",
	Short: "Spotter - Universal Kubernetes Security Engine",
	Long: `Spotter is a comprehensive Kubernetes security scanner that uses CEL-based rules
to identify security vulnerabilities, misconfigurations, and compliance violations
across your Kubernetes clusters, manifests, and CI/CD pipelines.

Spotter supports multiple deployment modes:
- CLI tool for on-demand scanning
- CI/CD integration for continuous security
- Admission controller for runtime protection
- IDE extensions for shift-left security

Examples:
  # Scan a live cluster
  spotter scan cluster
  
  # Scan YAML manifests
  spotter scan manifests ./k8s-manifests/
  
  # Validate security rules
  spotter rules validate ./rules/
  
  # Run as admission controller
  spotter server --mode=admission-controller`,
	SuggestionsMinimumDistance: 2,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if globalConfig != nil {
			initializeLogger(globalConfig)
		} else {
			defaultConfig, err := pkgconfig.DefaultConfig()
			if err != nil {
				// Fallback to basic logger if default config fails
				logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
				return
			}
			initializeLogger(defaultConfig)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Check if it's an unknown command error and provide suggestions
		if strings.Contains(err.Error(), "unknown command") {
			fmt.Fprintf(os.Stderr, "%s\n\nDid you mean one of these?\n", err.Error())
			fmt.Fprintf(os.Stderr, "  scan     - Scan Kubernetes resources for vulnerabilities\n")
			fmt.Fprintf(os.Stderr, "  rules    - Manage security rules\n")
			fmt.Fprintf(os.Stderr, "  packs    - Manage rule packs\n")
			fmt.Fprintf(os.Stderr, "  validate - Validate rules or manifests\n")
			fmt.Fprintf(os.Stderr, "\nRun 'spotter --help' for more information.\n")
		}
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ~/.spotter/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (trace, debug, info, warn, error, fatal, panic)")
	rootCmd.PersistentFlags().String("log-format", "text", "log format (text, json)")
	rootCmd.PersistentFlags().String("kubeconfig", "", "path to kubeconfig file")
	rootCmd.PersistentFlags().String("context", "", "kubernetes context to use")
	rootCmd.PersistentFlags().String("namespace", "", "kubernetes namespace to scan (default: all namespaces)")
	rootCmd.PersistentFlags().StringSlice("rules-path", []string{}, "paths to security rules directories or files")
	rootCmd.PersistentFlags().String("output", "table", "output format (table, json, yaml, sarif)")
	rootCmd.PersistentFlags().String("output-file", "", "output file path")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	rootCmd.PersistentFlags().String("timeout", "5m", "timeout for operations")

	// AI flags
	rootCmd.PersistentFlags().Bool("ai.enable", false, "enable AI recommendations in JSON output")
	rootCmd.PersistentFlags().String("ai.provider", "ollama", "ai provider: ollama|openai")
	rootCmd.PersistentFlags().String("ai.host", "http://localhost:11434", "ai endpoint host (for ollama)")
	rootCmd.PersistentFlags().String("ai.model", "llama3.2:latest", "ai model name")
	rootCmd.PersistentFlags().String("ai.apikey", "", "ai api key (for providers requiring auth)")

	// Bind AI flags to viper for configuration access
	viper.BindPFlag("ai.enable", rootCmd.PersistentFlags().Lookup("ai.enable"))
	viper.BindPFlag("ai.provider", rootCmd.PersistentFlags().Lookup("ai.provider"))
	viper.BindPFlag("ai.host", rootCmd.PersistentFlags().Lookup("ai.host"))
	viper.BindPFlag("ai.model", rootCmd.PersistentFlags().Lookup("ai.model"))
	viper.BindPFlag("ai.apikey", rootCmd.PersistentFlags().Lookup("ai.apikey"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Load configuration using the new consolidated config structure
	config, err := pkgconfig.LoadConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		// Continue with default config on error
		config, err = pkgconfig.DefaultConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading default config: %v\n", err)
			os.Exit(1)
		}
	}

	// Store the loaded config globally for access by other commands
	globalConfig = config

	// Initialize logger with the loaded configuration
	initializeLogger(config)
}

// initializeLogger sets up the logger based on configuration
func initializeLogger(config *pkgconfig.SpotterConfig) {
	// Parse log level from config
	levelStr := config.Logging.Level
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "trace", "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error", "fatal", "panic":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create handler based on format from config
	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	if strings.ToLower(config.Logging.Format) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove only the timestamp attribute, keep level and msg
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		})
	}

	// Create logger
	logger = slog.New(handler)

	// Set as default logger
	slog.SetDefault(logger)
}

// GetLogger returns the configured logger instance
func GetLogger() *slog.Logger {
	if logger == nil {
		if globalConfig != nil {
			initializeLogger(globalConfig)
		} else {
			defaultConfig, err := pkgconfig.DefaultConfig()
			if err != nil {
				// Fallback to basic logger if default config fails
				logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
				return logger
			}
			initializeLogger(defaultConfig)
		}
	}
	return logger
}
