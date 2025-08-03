//go:build wasm

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"syscall/js"

	"github.com/madhuakula/spotter/internal"
	"github.com/madhuakula/spotter/pkg/engine"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
	"gopkg.in/yaml.v3"
)

// Global variables for WASM
var (
	wasmReady = false
)

func main() {
	// Set up WASM exports
	js.Global().Set("spotter", js.ValueOf(map[string]interface{}{
		"scan":          js.FuncOf(wasmScan),
		"validateRules": js.FuncOf(wasmValidateRules),
		"getRules":      js.FuncOf(wasmGetRules),
		"version":       js.FuncOf(wasmVersion),
		"initialized":   js.FuncOf(wasmIsInitialized),
	}))

	wasmReady = true
	fmt.Println("Spotter WASM module initialized")

	// Keep the program running
	select {}
}

// wasmScan handles scanning operations from JavaScript
func wasmScan(this js.Value, args []js.Value) interface{} {
	// Capture the original arguments
	scanArgs := args
	
	// Create a promise
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					errorObj := map[string]interface{}{
						"error": fmt.Sprintf("Panic occurred: %v", r),
					}
					reject.Invoke(js.ValueOf(errorObj))
				}
			}()

			// Parse input arguments from the captured scanArgs
			if len(scanArgs) < 3 {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": "Missing required arguments. Expected: scanType, input, options",
				}))
				return
			}

			scanType := scanArgs[0].String()
			input := scanArgs[1].String()
			
			var options map[string]interface{}
			if len(scanArgs) > 2 && !scanArgs[2].IsUndefined() {
				optionsBytes := []byte(scanArgs[2].String())
				if err := json.Unmarshal(optionsBytes, &options); err != nil {
					reject.Invoke(js.ValueOf(map[string]interface{}{
						"error": fmt.Sprintf("Failed to parse options: %v", err),
					}))
					return
				}
			}

			// Perform the scan
			result, err := performScan(scanType, input, options)
			if err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": err.Error(),
				}))
				return
			}

			// Convert result to JSON and back to ensure JavaScript compatibility
			jsonBytes, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": fmt.Sprintf("Failed to serialize result: %v", err),
				}))
				return
			}

			var jsCompatibleResult interface{}
			if err := json.Unmarshal(jsonBytes, &jsCompatibleResult); err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": fmt.Sprintf("Failed to deserialize result: %v", err),
				}))
				return
			}

			resolve.Invoke(js.ValueOf(jsCompatibleResult))
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// wasmValidateRules handles rule validation from JavaScript
func wasmValidateRules(this js.Value, args []js.Value) interface{} {
	// Capture the original arguments
	validateArgs := args
	
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					errorObj := map[string]interface{}{
						"error": fmt.Sprintf("Panic occurred: %v", r),
					}
					reject.Invoke(js.ValueOf(errorObj))
				}
			}()

			if len(validateArgs) < 1 {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": "Missing required argument: rules content",
				}))
				return
			}

			rulesContent := validateArgs[0].String()
			result, err := validateRules(rulesContent)
			if err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": err.Error(),
				}))
				return
			}

			// Convert result to JSON and back to ensure JavaScript compatibility
			jsonBytes, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": fmt.Sprintf("Failed to serialize result: %v", err),
				}))
				return
			}

			var jsCompatibleResult interface{}
			if err := json.Unmarshal(jsonBytes, &jsCompatibleResult); err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": fmt.Sprintf("Failed to deserialize result: %v", err),
				}))
				return
			}

			resolve.Invoke(js.ValueOf(jsCompatibleResult))
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// wasmVersion returns version information
func wasmVersion(this js.Value, args []js.Value) interface{} {
	return js.ValueOf(map[string]interface{}{
		"version": "wasm-build",
		"runtime": "webassembly",
	})
}

// wasmIsInitialized returns initialization status
func wasmIsInitialized(this js.Value, args []js.Value) interface{} {
	return js.ValueOf(wasmReady)
}

// wasmGetRules returns all available built-in rules
func wasmGetRules(this js.Value, args []js.Value) interface{} {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					errorObj := map[string]interface{}{
						"error": fmt.Sprintf("Panic occurred: %v", r),
					}
					reject.Invoke(js.ValueOf(errorObj))
				}
			}()

			rules, err := getAllRules()
			if err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": err.Error(),
				}))
				return
			}

			// Convert result to JSON and back to ensure JavaScript compatibility
			jsonBytes, err := json.Marshal(rules)
			if err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": fmt.Sprintf("Failed to serialize rules: %v", err),
				}))
				return
			}

			var jsCompatibleResult interface{}
			if err := json.Unmarshal(jsonBytes, &jsCompatibleResult); err != nil {
				reject.Invoke(js.ValueOf(map[string]interface{}{
					"error": fmt.Sprintf("Failed to deserialize rules: %v", err),
				}))
				return
			}

			resolve.Invoke(js.ValueOf(jsCompatibleResult))
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// getAllRules returns all available built-in rules with their metadata
func getAllRules() (map[string]interface{}, error) {
	rulesFS := internal.GetBuiltinRulesFS()
	categories := make(map[string][]map[string]interface{})
	allRules := make([]map[string]interface{}, 0)

	err := fs.WalkDir(rulesFS, "rules/builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		// Read rule file
		content, err := fs.ReadFile(rulesFS, path)
		if err != nil {
			return fmt.Errorf("failed to read rule file %s: %v", path, err)
		}

		// Parse YAML
		var rule map[string]interface{}
		if err := yaml.Unmarshal(content, &rule); err != nil {
			return fmt.Errorf("failed to parse rule file %s: %v", path, err)
		}

		// Extract metadata
		ruleInfo := extractRuleInfo(rule, path)
		allRules = append(allRules, ruleInfo)

		// Group by category
		category := ruleInfo["category"].(string)
		if categories[category] == nil {
			categories[category] = make([]map[string]interface{}, 0)
		}
		categories[category] = append(categories[category], ruleInfo)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %v", err)
	}

	return map[string]interface{}{
		"categories": categories,
		"rules":      allRules,
		"total":      len(allRules),
	}, nil
}

// extractRuleInfo extracts key information from a rule for UI display
func extractRuleInfo(rule map[string]interface{}, path string) map[string]interface{} {
	ruleInfo := map[string]interface{}{
		"id":          "unknown",
		"name":        "Unknown Rule",
		"description": "No description available",
		"severity":    "medium",
		"category":    "Unknown",
		"subcategory": "Unknown",
		"path":        path,
		"enabled":     true, // Default to enabled
	}

	// Extract metadata
	if metadata, ok := rule["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			ruleInfo["id"] = name
		}
	}

	// Extract spec information
	if spec, ok := rule["spec"].(map[string]interface{}); ok {
		if name, ok := spec["name"].(string); ok {
			ruleInfo["name"] = name
		}
		if description, ok := spec["description"].(string); ok {
			ruleInfo["description"] = description
		}
		if category, ok := spec["category"].(string); ok {
			ruleInfo["category"] = category
		}
		if subcategory, ok := spec["subcategory"].(string); ok {
			ruleInfo["subcategory"] = subcategory
		}

		// Handle severity (can be string or object)
		if severity, ok := spec["severity"]; ok {
			switch s := severity.(type) {
			case string:
				ruleInfo["severity"] = strings.ToLower(s)
			case map[string]interface{}:
				if level, ok := s["level"].(string); ok {
					ruleInfo["severity"] = strings.ToLower(level)
				}
			}
		}
	}

	// Extract category from path if not found in spec
	if ruleInfo["category"] == "Unknown" {
		pathParts := strings.Split(path, "/")
		if len(pathParts) >= 3 {
			categoryDir := pathParts[2]
			// Convert kebab-case to Title Case
			categoryDir = strings.ReplaceAll(categoryDir, "-", " ")
			words := strings.Fields(categoryDir)
			for i, word := range words {
				words[i] = strings.Title(word)
			}
			ruleInfo["category"] = strings.Join(words, " ")
		}
	}

	return ruleInfo
}

// performScan executes the actual scanning logic using the full rule engine
func performScan(scanType, input string, options map[string]interface{}) (map[string]interface{}, error) {
	ctx := context.Background()
	
	// Parse YAML input
	var manifest map[string]interface{}
	if err := yaml.Unmarshal([]byte(input), &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}
	
	// Debug: log manifest info
	fmt.Printf("WASM Debug: Processing manifest - Kind: %v, ApiVersion: %v\n", manifest["kind"], manifest["apiVersion"])
	
	// Load all built-in rules using the same method as CLI
	rules, err := loadAllBuiltinRules()
	if err != nil {
		return nil, fmt.Errorf("failed to load built-in rules: %v", err)
	}
	
	// Debug: log rules loaded
	fmt.Printf("WASM Debug: Loaded %d built-in rules\n", len(rules))
	
	// Filter rules based on selected rules from options
	selectedRules := make(map[string]bool)
	if rulesList, ok := options["selectedRules"].([]interface{}); ok {
		fmt.Printf("WASM Debug: Found selectedRules option with %d rules\n", len(rulesList))
		for _, rule := range rulesList {
			if ruleStr, ok := rule.(string); ok {
				selectedRules[ruleStr] = true
				fmt.Printf("WASM Debug: Added selected rule: %s\n", ruleStr)
			}
		}
	} else {
		fmt.Printf("WASM Debug: No selectedRules option found in options\n")
	}
	
	// Filter rules if specific rules are selected
	var filteredRules []*models.SecurityRule
	if len(selectedRules) > 0 {
		fmt.Printf("WASM Debug: Filtering %d rules based on %d selected rules\n", len(rules), len(selectedRules))
		for _, rule := range rules {
			// Match against metadata.name instead of spec.id since frontend passes metadata names
			if selectedRules[rule.Metadata.Name] {
				filteredRules = append(filteredRules, rule)
				fmt.Printf("WASM Debug: Selected rule: %s (ID: %s)\n", rule.Metadata.Name, rule.Spec.ID)
			}
		}
	} else {
		fmt.Printf("WASM Debug: No specific rules selected, using all %d rules\n", len(rules))
		filteredRules = rules
	}
	
	fmt.Printf("WASM Debug: Final filtered rules count: %d\n", len(filteredRules))
	
	// Initialize CEL engine
	celEngine, err := engine.NewCELEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL engine: %v", err)
	}
	
	fmt.Printf("WASM Debug: CEL engine created successfully\n")
	
	// Try to evaluate rules one by one to get better error handling
	var results []*models.ValidationResult
	for _, rule := range filteredRules {
		result, err := celEngine.EvaluateRule(ctx, rule, manifest)
		if err != nil {
			fmt.Printf("WASM Debug: Error evaluating rule %s: %v\n", rule.Spec.ID, err)
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}
	
	// Convert results to the expected format
	findings := []map[string]interface{}{}
	summary := map[string]interface{}{
		"total":    0,
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	
	// Debug: log how many results we got
	fmt.Printf("WASM Debug: Got %d results from %d rules\n", len(results), len(filteredRules))
	
	for _, result := range results {
		// Debug: log each result
		fmt.Printf("WASM Debug: Rule %s, Passed: %t, Message: %s\n", result.RuleID, result.Passed, result.Message)
		
		if !result.Passed {
			finding := map[string]interface{}{
				"rule":        result.RuleID,
				"severity":    strings.ToLower(string(result.Severity)),
				"message":     result.Message,
				"resource":    getResourceName(manifest),
				"namespace":   getNamespace(manifest),
				"remediation": result.Remediation,
			}
			findings = append(findings, finding)
			
			// Update summary
			severityStr := strings.ToLower(string(result.Severity))
			if count, exists := summary[severityStr].(int); exists {
				summary[severityStr] = count + 1
			}
		}
	}
	
	summary["total"] = len(findings)
	
	result := map[string]interface{}{
		"scanType":      scanType,
		"findings":      findings,
		"summary":       summary,
		"selectedRules": len(filteredRules),
		"totalRules":    len(rules),
	}

	return result, nil
}



// getResourceName extracts the resource name from manifest
func getResourceName(manifest map[string]interface{}) string {
	if metadata, ok := manifest["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			return name
		}
	}
	return "unknown"
}

// getNamespace extracts the namespace from manifest
func getNamespace(manifest map[string]interface{}) string {
	if metadata, ok := manifest["metadata"].(map[string]interface{}); ok {
		if namespace, ok := metadata["namespace"].(string); ok {
			return namespace
		}
	}
	return "default"
}

// loadAllBuiltinRules loads all built-in security rules using the same method as CLI
func loadAllBuiltinRules() ([]*models.SecurityRule, error) {
	ctx := context.Background()
	parser := parser.NewYAMLParser(true)
	
	rulesFS := internal.GetBuiltinRulesFS()
	rules, err := parser.ParseRulesFromFS(ctx, rulesFS, "rules/builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse built-in rules: %v", err)
	}
	
	return rules, nil
}

// validateRules validates security rules
func validateRules(rulesContent string) (map[string]interface{}, error) {
	var rules []map[string]interface{}
	var errors []string
	valid := true
	
	// Split multiple YAML documents
	documents := strings.Split(rulesContent, "---")
	
	for i, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		
		var rule map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &rule); err != nil {
			errors = append(errors, fmt.Sprintf("Document %d: Invalid YAML: %v", i+1, err))
			valid = false
			continue
		}
		
		// Basic rule validation
		ruleName := "unknown"
		if metadata, ok := rule["metadata"].(map[string]interface{}); ok {
			if name, ok := metadata["name"].(string); ok {
				ruleName = name
			}
		}
		
		ruleErrors := validateRule(rule)
		if len(ruleErrors) > 0 {
			valid = false
			for _, err := range ruleErrors {
				errors = append(errors, fmt.Sprintf("Rule '%s': %s", ruleName, err))
			}
		}
		
		rules = append(rules, map[string]interface{}{
			"name":   ruleName,
			"status": func() string {
				if len(ruleErrors) > 0 {
					return "invalid"
				}
				return "valid"
			}(),
			"errors": ruleErrors,
		})
	}
	
	result := map[string]interface{}{
		"valid":  valid,
		"rules":  rules,
		"errors": errors,
	}

	return result, nil
}

// validateRule validates a single security rule
func validateRule(rule map[string]interface{}) []string {
	var errors []string
	
	// Check required fields
	if _, ok := rule["apiVersion"]; !ok {
		errors = append(errors, "missing required field: apiVersion")
	}
	
	if _, ok := rule["kind"]; !ok {
		errors = append(errors, "missing required field: kind")
	}
	
	if metadata, ok := rule["metadata"].(map[string]interface{}); ok {
		if _, ok := metadata["name"]; !ok {
			errors = append(errors, "missing required field: metadata.name")
		}
	} else {
		errors = append(errors, "missing required field: metadata")
	}
	
	if spec, ok := rule["spec"].(map[string]interface{}); ok {
		// Check spec fields
		if _, ok := spec["title"]; !ok {
			errors = append(errors, "missing required field: spec.title")
		}
		
		if _, ok := spec["description"]; !ok {
			errors = append(errors, "missing required field: spec.description")
		}
		
		if severity, ok := spec["severity"].(string); ok {
			validSeverities := []string{"critical", "high", "medium", "low"}
			isValid := false
			for _, valid := range validSeverities {
				if severity == valid {
					isValid = true
					break
				}
			}
			if !isValid {
				errors = append(errors, "invalid severity: must be one of critical, high, medium, low")
			}
		} else {
			errors = append(errors, "missing or invalid field: spec.severity")
		}
		
		if _, ok := spec["expression"]; !ok {
			errors = append(errors, "missing required field: spec.expression")
		}
	} else {
		errors = append(errors, "missing required field: spec")
	}
	
	return errors
}