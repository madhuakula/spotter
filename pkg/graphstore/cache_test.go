package graphstore

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGetDefaultCacheDir(t *testing.T) {
	// Save original environment
	originalXDGCache := os.Getenv("XDG_CACHE_HOME")
	originalLocalAppData := os.Getenv("LOCALAPPDATA")

	defer func() {
		// Restore original environment
		if originalXDGCache != "" {
			_ = os.Setenv("XDG_CACHE_HOME", originalXDGCache)
		} else {
			_ = os.Unsetenv("XDG_CACHE_HOME")
		}
		if originalLocalAppData != "" {
			_ = os.Setenv("LOCALAPPDATA", originalLocalAppData)
		} else {
			_ = os.Unsetenv("LOCALAPPDATA")
		}
	}()

	switch runtime.GOOS {
	case "linux", "darwin":
		// Test with XDG_CACHE_HOME set
		_ = os.Setenv("XDG_CACHE_HOME", "/tmp/test-cache")
		cacheDir, err := GetDefaultCacheDir()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		expected := "/tmp/test-cache/spotter/kuzu"
		if cacheDir != expected {
			t.Errorf("Expected cache dir '%s', got '%s'", expected, cacheDir)
		}

		// Test without XDG_CACHE_HOME
		_ = os.Unsetenv("XDG_CACHE_HOME")
		cacheDir, err = GetDefaultCacheDir()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		homeDir, _ := os.UserHomeDir()
		expected = filepath.Join(homeDir, ".cache", "spotter", "kuzu")
		if cacheDir != expected {
			t.Errorf("Expected cache dir '%s', got '%s'", expected, cacheDir)
		}

	case "windows":
		// Test with LOCALAPPDATA set
		_ = os.Setenv("LOCALAPPDATA", "C:\\Users\\Test\\AppData\\Local")
		cacheDir, err := GetDefaultCacheDir()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		expected := "C:\\Users\\Test\\AppData\\Local\\spotter\\kuzu"
		if cacheDir != expected {
			t.Errorf("Expected cache dir '%s', got '%s'", expected, cacheDir)
		}
	}
}

func TestGetSystemCacheDir(t *testing.T) {
	systemDir := GetSystemCacheDir()

	switch runtime.GOOS {
	case "linux", "darwin":
		expected := "/var/lib/spotter/kuzu"
		if systemDir != expected {
			t.Errorf("Expected system cache dir '%s', got '%s'", expected, systemDir)
		}
	case "windows":
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = "C:\\ProgramData" // Default fallback
		}
		expected := filepath.Join(programData, "spotter", "kuzu")
		if systemDir != expected {
			t.Errorf("Expected system cache dir '%s', got '%s'", expected, systemDir)
		}
	}
}

func TestResolveCacheDir(t *testing.T) {
	// Test with explicit cache dir
	config := &CacheConfig{
		CacheDir: "/custom/cache/dir",
	}

	cacheDir, err := ResolveCacheDir(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if cacheDir != "/custom/cache/dir" {
		t.Errorf("Expected cache dir '/custom/cache/dir', got '%s'", cacheDir)
	}

	// Test without explicit cache dir (should use default)
	config = &CacheConfig{}

	cacheDir, err = ResolveCacheDir(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should return a valid path
	if cacheDir == "" {
		t.Error("Expected non-empty cache dir")
	}
}

func TestGetCachePath(t *testing.T) {
	config := &CacheConfig{
		CacheDir: "/tmp/test-cache",
		Target:   "test-target",
	}

	cachePath, err := GetCachePath(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should contain the base directory
	if !strings.HasPrefix(cachePath, "/tmp/test-cache") {
		t.Errorf("Expected cache path to start with '/tmp/test-cache', got '%s'", cachePath)
	}

	// Should contain a hash-based subdirectory
	_, subDir := filepath.Split(cachePath)
	if len(subDir) != 16 { // Hash should be 16 characters
		t.Errorf("Expected hash subdirectory of length 16, got '%s' (length %d)", subDir, len(subDir))
	}
}

func TestGenerateCacheKey(t *testing.T) {
	// Test that same inputs produce same key
	key1 := GenerateCacheKey("target1", "v1")
	key2 := GenerateCacheKey("target1", "v1")

	if key1 != key2 {
		t.Errorf("Expected same cache key for same inputs, got '%s' and '%s'", key1, key2)
	}

	// Test that different inputs produce different keys
	key3 := GenerateCacheKey("target2", "v1")
	if key1 == key3 {
		t.Errorf("Expected different cache keys for different targets, got same key '%s'", key1)
	}

	key4 := GenerateCacheKey("target1", "v2")
	if key1 == key4 {
		t.Errorf("Expected different cache keys for different schema versions, got same key '%s'", key1)
	}

	// Test key length
	if len(key1) != 16 {
		t.Errorf("Expected cache key length of 16, got %d", len(key1))
	}
}
