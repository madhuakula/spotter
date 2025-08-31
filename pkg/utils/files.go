package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// FileCollectionOptions configures file collection behavior
type FileCollectionOptions struct {
	Recursive      bool
	Extensions     []string
	FollowSymlinks bool
	ExcludeTest    bool // Exclude test files (ending with -test.yaml or -test.yml)
}

// CollectFiles collects files from a path based on the provided options
func CollectFiles(path string, options FileCollectionOptions) ([]string, error) {
	var files []string

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		// Single file
		if hasValidExtension(path, options.Extensions) && (!options.ExcludeTest || !isTestFile(path)) {
			return []string{path}, nil
		}
		return nil, nil
	}

	// Directory
	if options.Recursive {
		err = filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Skip symlinks if not following
			if d.Type()&os.ModeSymlink != 0 && !options.FollowSymlinks {
				return nil
			}
			if !d.IsDir() && hasValidExtension(filePath, options.Extensions) && (!options.ExcludeTest || !isTestFile(filePath)) {
				files = append(files, filePath)
			}
			return nil
		})
	} else {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			// Skip symlinks if not following
			if entry.Type()&os.ModeSymlink != 0 && !options.FollowSymlinks {
				continue
			}
			if !entry.IsDir() {
				filePath := filepath.Join(path, entry.Name())
				if hasValidExtension(filePath, options.Extensions) && (!options.ExcludeTest || !isTestFile(filePath)) {
					files = append(files, filePath)
				}
			}
		}
	}

	return files, err
}

// hasValidExtension checks if the file has a valid extension
func hasValidExtension(filePath string, extensions []string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, validExt := range extensions {
		if ext == strings.ToLower(validExt) {
			return true
		}
	}
	return false
}

// isTestFile checks if the file is a test file (ends with -test.yaml or -test.yml)
func isTestFile(filePath string) bool {
	baseName := filepath.Base(filePath)
	return strings.HasSuffix(baseName, "-test.yaml") || strings.HasSuffix(baseName, "-test.yml")
}