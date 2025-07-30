package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/madhuakula/spotter/pkg/version"
)

var (
	versionOutputFormat string
	versionShort        bool
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long: `Display detailed version information including:
- Semantic version
- Git commit hash
- Build date
- Go version used for compilation
- Target platform

Supports multiple output formats for integration with CI/CD pipelines.`,
	Example: `  # Display version information
  spotter version
  
  # Display short version
  spotter version --short
  
  # Output as JSON
  spotter version --output json
  
  # Output as YAML
  spotter version --output yaml`,
	Run: runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Add flags
	versionCmd.Flags().StringVarP(&versionOutputFormat, "output", "o", "text",
		"Output format (text, json, yaml)")
	versionCmd.Flags().BoolVarP(&versionShort, "short", "s", false,
		"Display short version information")
}

func runVersion(cmd *cobra.Command, args []string) {
	versionInfo := version.Get()

	// Handle short version
	if versionShort {
		fmt.Println(versionInfo.Short())
		return
	}

	// Handle different output formats
	switch versionOutputFormat {
	case "json":
		output, err := json.MarshalIndent(versionInfo, "", "  ")
		if err != nil {
			logger.Error("Failed to marshal version info to JSON", "error", err)
			os.Exit(1)
		}
		fmt.Println(string(output))

	case "yaml":
		fmt.Printf("version: %s\n", versionInfo.Version)
		fmt.Printf("commit_hash: %s\n", versionInfo.CommitHash)
		fmt.Printf("build_date: %s\n", versionInfo.BuildDate)
		fmt.Printf("go_version: %s\n", versionInfo.GoVersion)
		fmt.Printf("platform: %s\n", versionInfo.Platform)

	case "text":
		fallthrough
	default:
		fmt.Println(versionInfo.String())
		
		// Add development build warning
		if version.IsDevBuild() {
			fmt.Println("\n⚠️  This is a development build. Use official releases for production.")
		}
	}
}