package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/hub"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// hubCmd represents the hub command
var hubCmd = &cobra.Command{
	Use:   "hub",
	Short: "Manage Spotter rules from the central hub",
	Long: `The hub command allows you to search, pull, and manage Spotter security rules
from the central rule repository. You can search for specific rules, pull individual
rules or entire rule packs to use in your security scans.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Show help when no subcommand is provided
		cmd.Help()
	},
}

// hubSearchCmd represents the hub search command
var hubSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search for rules in the Spotter hub",
	Long: `Search for security rules in the Spotter hub repository.
You can search by rule name, category, severity, or keywords.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]
		if err := searchRules(cmd, query); err != nil {
			fmt.Fprintf(os.Stderr, "Error searching rules: %v\n", err)
			os.Exit(1)
		}
	},
}

// hubPullCmd represents the hub pull command
var hubPullCmd = &cobra.Command{
	Use:   "pull [rule-name|rule-pack]",
	Short: "Pull rules or rule packs from the Spotter hub",
	Long: `Pull specific rules or entire rule packs from the Spotter hub repository.
Rules will be downloaded and cached locally for use in security scans.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		if err := pullRules(cmd, target); err != nil {
			fmt.Fprintf(os.Stderr, "Error pulling rules: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// Add hub command to root
	rootCmd.AddCommand(hubCmd)
	
	// Add subcommands to hub
	hubCmd.AddCommand(hubSearchCmd)
	hubCmd.AddCommand(hubPullCmd)
	
	// Add flags for search command
	hubSearchCmd.Flags().StringP("category", "c", "", "Filter by category")
	hubSearchCmd.Flags().StringP("severity", "s", "", "Filter by severity level")
	hubSearchCmd.Flags().BoolP("json", "j", false, "Output results in JSON format")
	
	// Add flags for pull command
	hubPullCmd.Flags().BoolP("force", "f", false, "Force overwrite existing rules")
	hubPullCmd.Flags().StringP("output", "o", "", "Output directory for pulled rules")
}

// getHubClient creates a new hub client with configuration from environment variables and defaults
func getHubClient() hub.HubClient {
	// Initialize configuration
	cfg, err := config.InitializeConfig()
	if err != nil {
		fmt.Printf("Warning: failed to initialize config, using defaults: %v\n", err)
		cfg = config.DefaultConfig()
	}
	
	// Create client with configuration
	client := hub.NewClientWithConfig(cfg)
	
	// Ensure the client implements the interface
	var _ hub.HubClient = client
	
	return client
}

// searchRules searches for rules in the hub
func searchRules(cmd *cobra.Command, query string) error {
	client := getHubClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := hub.SearchRequest{
		Query: query,
		Limit: 20,
	}

	// Get flags from cobra command
	if category, _ := cmd.Flags().GetString("category"); category != "" {
		req.Category = category
	}
	if severity, _ := cmd.Flags().GetString("severity"); severity != "" {
		req.Severity = severity
	}

	fmt.Printf("Searching for rules matching: %s\n", query)
	resp, err := client.SearchRules(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to search rules: %w", err)
	}

	if len(resp.Rules) == 0 {
		fmt.Println("No rules found matching your search criteria.")
		return nil
	}

	// Check if JSON output is requested
	if jsonOutput, _ := cmd.Flags().GetBool("json"); jsonOutput {
		// Output results in JSON format
		jsonData, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Display results in table format
	fmt.Printf("\nFound %d rule(s):\n\n", len(resp.Rules))
	for _, rule := range resp.Rules {
		fmt.Printf("ID: %s\n", rule.ID)
		fmt.Printf("Name: %s\n", rule.Name)
		fmt.Printf("Description: %s\n", rule.Description)
		fmt.Printf("Category: %s\n", rule.Category)
		fmt.Printf("Severity: %s\n", rule.Severity)
		fmt.Printf("Version: %s\n", rule.Version)
		fmt.Printf("Author: %s\n", rule.Author)
		fmt.Println("---")
	}

	return nil
}

// pullRules pulls rules or rule packs from the hub
func pullRules(cmd *cobra.Command, target string) error {
	client := getHubClient()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Printf("Pulling rules/rule pack: %s\n", target)

	// Get output directory from flag or use default
	outputDir, _ := cmd.Flags().GetString("output")
	if outputDir == "" {
		// Default to current directory + rules/
		outputDir = "rules"
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	force, _ := cmd.Flags().GetBool("force")

	// Try to get as a single rule first
	rule, err := client.GetRule(ctx, target)
	if err == nil && rule != nil {
		fmt.Printf("Successfully pulled rule: %s\n", rule.GetTitle())
		
		// Save rule to cache
		if hubClient, ok := client.(*hub.Client); ok {
			if err := hubClient.SaveRuleToCache(rule); err != nil {
				return fmt.Errorf("failed to save rule to cache: %w", err)
			}
			fmt.Printf("Rule %s saved to cache\n", rule.GetID())
		} else {
			// Fallback to old behavior for compatibility
			filename := fmt.Sprintf("%s.yaml", rule.GetID())
			filePath := filepath.Join(outputDir, filename)
			
			if err := saveRuleToFile(rule, filePath, force); err != nil {
				return fmt.Errorf("failed to save rule: %w", err)
			}
			
			fmt.Printf("Rule saved to: %s\n", filePath)
		}
		return nil
	}

	// Try to get as a rule pack
	pack, err := client.GetRulePack(ctx, target)
	if err == nil && pack != nil {
		fmt.Printf("Successfully pulled rule pack: %s\n", pack.ID)
		fmt.Printf("Contains %d rules\n", len(pack.Rules))
		
		// Save rule pack to cache
		if hubClient, ok := client.(*hub.Client); ok {
			if err := hubClient.SaveRulePackToCache(pack); err != nil {
				return fmt.Errorf("failed to save rule pack to cache: %w", err)
			}
			fmt.Printf("Rule pack %s saved to cache\n", pack.ID)
			
			// Pull and save each rule in the pack to cache
			for _, ruleID := range pack.Rules {
				rule, err := client.GetRule(ctx, ruleID)
				if err != nil {
					fmt.Printf("Warning: failed to pull rule %s: %v\n", ruleID, err)
					continue
				}
				
				// Save rule to cache
				if err := hubClient.SaveRuleToCache(rule); err != nil {
					fmt.Printf("Warning: failed to save rule %s to cache: %v\n", rule.GetID(), err)
					continue
				}
				
				fmt.Printf("Saved rule: %s\n", rule.GetID())
			}
		} else {
			// Fallback to old behavior for compatibility
			packDir := filepath.Join(outputDir, pack.ID)
			if err := os.MkdirAll(packDir, 0755); err != nil {
				return fmt.Errorf("failed to create pack directory: %w", err)
			}
			
			// Save each rule in the pack
			for _, ruleID := range pack.Rules {
				// Get the full rule details
				rule, err := client.GetRule(ctx, ruleID)
				if err != nil {
					fmt.Printf("Warning: failed to get rule %s: %v\n", ruleID, err)
					continue
				}
				
				filename := fmt.Sprintf("%s.yaml", rule.GetID())
				filePath := filepath.Join(packDir, filename)
				
				if err := saveRuleToFile(rule, filePath, force); err != nil {
					fmt.Printf("Warning: failed to save rule %s: %v\n", ruleID, err)
					continue
				}
				
				fmt.Printf("Saved rule: %s\n", filename)
			}
			
			fmt.Printf("Rule pack saved to: %s\n", packDir)
		}
		return nil
	}

	return fmt.Errorf("could not find rule or rule pack: %s", target)
}

// saveRuleToFile saves a SpotterRule to a YAML file
func saveRuleToFile(rule *models.SpotterRule, filePath string, force bool) error {
	// Check if file exists and force flag is not set
	if _, err := os.Stat(filePath); err == nil && !force {
		return fmt.Errorf("file %s already exists, use --force to overwrite", filePath)
	}

	// Marshal rule to YAML
	data, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule to YAML: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}