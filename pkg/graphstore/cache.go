package graphstore

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// GetDefaultCacheDir returns the default cache directory following XDG Base Directory specification
func GetDefaultCacheDir() (string, error) {
	var baseDir string

	switch runtime.GOOS {
	case "linux", "darwin":
		// Follow XDG Base Directory specification
		if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
			baseDir = xdgCache
		} else {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("failed to get user home directory: %w", err)
			}
			baseDir = filepath.Join(homeDir, ".cache")
		}
	case "windows":
		// Use Windows-specific cache directory
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			baseDir = localAppData
		} else {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("failed to get user home directory: %w", err)
			}
			baseDir = filepath.Join(homeDir, "AppData", "Local")
		}
	default:
		// Fallback for other operating systems
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		baseDir = filepath.Join(homeDir, ".cache")
	}

	return filepath.Join(baseDir, "spotter", "kuzu"), nil
}

// GetSystemCacheDir returns the system-wide cache directory
func GetSystemCacheDir() string {
	switch runtime.GOOS {
	case "linux", "darwin":
		return "/var/lib/spotter/kuzu"
	case "windows":
		return filepath.Join(os.Getenv("PROGRAMDATA"), "spotter", "kuzu")
	default:
		return "/var/lib/spotter/kuzu"
	}
}

// ResolveCacheDir resolves the cache directory based on configuration
func ResolveCacheDir(config *CacheConfig) (string, error) {
	if config.CacheDir != "" {
		return config.CacheDir, nil
	}

	// Check if running as root and prefer system-wide cache
	if os.Geteuid() == 0 {
		return GetSystemCacheDir(), nil
	}

	return GetDefaultCacheDir()
}

// GetCachePath returns the full cache path for a specific target
func GetCachePath(config *CacheConfig) (string, error) {
	baseDir, err := ResolveCacheDir(config)
	if err != nil {
		return "", fmt.Errorf("failed to resolve cache directory: %w", err)
	}

	// Generate cache key based on target
	cacheKey := GenerateCacheKey(config.Target, "v1") // v1 is schema version
	return filepath.Join(baseDir, cacheKey), nil
}

// EnsureCacheDir creates the cache directory if it doesn't exist
func EnsureCacheDir(path string) error {
	// Determine appropriate permissions based on the path
	var perm os.FileMode = 0700 // Default to user-only

	// If it's a system-wide path, use more permissive permissions
	if filepath.HasPrefix(path, "/var/lib") || strings.Contains(path, "ProgramData") {
		perm = 0750
	}

	return os.MkdirAll(path, perm)
}
