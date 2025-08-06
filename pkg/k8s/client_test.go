package k8s

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/util/homedir"
)

func TestBuildConfigPriority(t *testing.T) {
	// Save original environment
	originalKubeconfig := os.Getenv("KUBECONFIG")
	defer func() {
		if originalKubeconfig != "" {
			os.Setenv("KUBECONFIG", originalKubeconfig)
		} else {
			os.Unsetenv("KUBECONFIG")
		}
	}()

	// Test case 1: KUBECONFIG environment variable takes priority
	t.Run("KUBECONFIG environment variable priority", func(t *testing.T) {
		envKubeconfig := "/env/kubeconfig/path"
		flagKubeconfig := "/flag/kubeconfig/path"

		os.Setenv("KUBECONFIG", envKubeconfig)

		// Create a mock config loader to test the path selection
		// Since buildConfig() returns an error when the file doesn't exist,
		// we'll test the path resolution logic by checking the error message
		_, err := buildConfig(flagKubeconfig, "")

		// The error should contain the env kubeconfig path, not the flag path
		if err == nil {
			t.Fatal("Expected error due to non-existent config file")
		}

		// Check if the error mentions the environment kubeconfig path
		if !containsPath(err.Error(), envKubeconfig) {
			t.Errorf("Expected error to mention env kubeconfig path %s, got: %v", envKubeconfig, err)
		}
	})

	// Test case 2: Flag takes priority when KUBECONFIG env var is not set
	t.Run("Flag kubeconfig priority when env not set", func(t *testing.T) {
		os.Unsetenv("KUBECONFIG")
		flagKubeconfig := "/flag/kubeconfig/path"

		_, err := buildConfig(flagKubeconfig, "")

		if err == nil {
			t.Fatal("Expected error due to non-existent config file")
		}

		// Check if the error mentions the flag kubeconfig path
		if !containsPath(err.Error(), flagKubeconfig) {
			t.Errorf("Expected error to mention flag kubeconfig path %s, got: %v", flagKubeconfig, err)
		}
	})

	// Test case 3: Default ~/.kube/config when neither env var nor flag is set
	t.Run("Default kubeconfig path when neither env nor flag set", func(t *testing.T) {
		os.Unsetenv("KUBECONFIG")

		config, err := buildConfig("", "")

		// The behavior should be:
		// 1. Try in-cluster config - may succeed or fail
		// 2. If in-cluster fails, try default kubeconfig - will likely fail

		if err == nil && config != nil {
			// In-cluster config succeeded - this is valid behavior
			// We can't test the fallback path in this case, but the priority logic is correct
			t.Logf("In-cluster config succeeded, which is valid behavior")
			return
		}

		if err == nil && config == nil {
			t.Fatal("Unexpected state: no error but no config")
		}

		// If we get here, there was an error (expected for default path)
		errorMsg := err.Error()
		defaultPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

		// Check if it's related to config loading
		if containsPath(errorMsg, defaultPath) ||
			containsText(errorMsg, "no such file") ||
			containsText(errorMsg, "cannot find") ||
			containsText(errorMsg, "unable to load") ||
			containsText(errorMsg, "invalid configuration") {
			// This is expected - the function tried to load the config and failed
			return
		}

		t.Errorf("Expected error related to config loading, got: %v", err)
	})
}

func TestBuildConfigContext(t *testing.T) {
	// Test that context is properly set in config overrides
	t.Run("Context override", func(t *testing.T) {
		os.Unsetenv("KUBECONFIG")
		testContext := "test-context"

		// We can't easily test the actual context setting without a valid kubeconfig file,
		// but we can verify the function doesn't panic and handles context parameter
		_, err := buildConfig("", testContext)

		// Should get an error due to missing config file, but shouldn't panic
		if err == nil {
			t.Fatal("Expected error due to non-existent config file or in-cluster config")
		}

		// The error could be related to context not existing, which is fine
		// What we're testing is that the function doesn't panic with context parameter
		errorMsg := err.Error()

		// As long as we get a reasonable error (not a panic), the test passes
		if containsText(errorMsg, "panic") {
			t.Errorf("Function should not panic when context is provided, got: %v", err)
		}
	})
}

// Helper function to check if error message contains a file path
func containsPath(errorMsg, path string) bool {
	return containsText(errorMsg, path)
}

// Helper function to check if string contains substring
func containsText(text, substring string) bool {
	return len(substring) > 0 && len(text) > 0 &&
		(text == substring || len(text) >= len(substring) &&
			findSubstring(text, substring))
}

// Simple substring search
func findSubstring(text, substring string) bool {
	if len(substring) > len(text) {
		return false
	}
	for i := 0; i <= len(text)-len(substring); i++ {
		if text[i:i+len(substring)] == substring {
			return true
		}
	}
	return false
}
