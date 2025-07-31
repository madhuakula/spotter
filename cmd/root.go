package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	logger  *slog.Logger
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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initializeLogger()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Ensure logger is initialized before using it
		if logger == nil {
			initializeLogger()
		}
		logger.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.spotter.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (trace, debug, info, warn, error, fatal, panic)")
	rootCmd.PersistentFlags().String("log-format", "text", "log format (text, json)")
	rootCmd.PersistentFlags().String("kubeconfig", "", "path to kubeconfig file")
	rootCmd.PersistentFlags().String("context", "", "kubernetes context to use")
	rootCmd.PersistentFlags().String("namespace", "", "kubernetes namespace to scan (default: all namespaces)")
	rootCmd.PersistentFlags().StringSlice("rules-path", []string{"./rules"}, "paths to security rules directories or files")
	rootCmd.PersistentFlags().String("output", "table", "output format (table, json, yaml, sarif, junit)")
	rootCmd.PersistentFlags().String("output-file", "", "output file path")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	rootCmd.PersistentFlags().Int("max-concurrency", 10, "maximum number of concurrent operations")
	rootCmd.PersistentFlags().String("timeout", "5m", "timeout for operations")

	// Bind flags to viper
	bindFlags := []struct {
		name string
		flag string
	}{
		{"verbose", "verbose"},
		{"log-level", "log-level"},
		{"log-format", "log-format"},
		{"kubeconfig", "kubeconfig"},
		{"context", "context"},
		{"namespace", "namespace"},
		{"rules-path", "rules-path"},
		{"output", "output"},
		{"output-file", "output-file"},
		{"no-color", "no-color"},
		{"max-concurrency", "max-concurrency"},
	}

	for _, bf := range bindFlags {
		if err := viper.BindPFlag(bf.name, rootCmd.PersistentFlags().Lookup(bf.flag)); err != nil {
			logger.Error("Failed to bind flag", "name", bf.name, "error", err)
		}
	}
	if err := viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout")); err != nil {
		logger.Error("Failed to bind timeout flag", "error", err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".spotter" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".spotter")
	}

	// Environment variables
	viper.SetEnvPrefix("SPOTTER")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// initializeLogger sets up the logger based on configuration
func initializeLogger() {
	// Parse log level
	levelStr := viper.GetString("log-level")
	var level slog.Level
	switch levelStr {
	case "trace", "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error", "fatal", "panic":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create handler based on format
	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	if viper.GetString("log-format") == "json" {
		handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, handlerOpts)
	}

	// Create logger
	logger = slog.New(handler)

	// Set as default logger
	slog.SetDefault(logger)
}

// GetLogger returns the configured logger instance
func GetLogger() *slog.Logger {
	if logger == nil {
		initializeLogger()
	}
	return logger
}
