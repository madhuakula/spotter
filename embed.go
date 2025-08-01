package main

import (
	"embed"
	"io/fs"
)

// BuiltinRules contains all built-in security rules embedded in the binary
//
//go:embed internal/builtin/**/*.yaml
var BuiltinRules embed.FS

// GetBuiltinRulesFS returns the embedded filesystem containing built-in rules
func GetBuiltinRulesFS() fs.FS {
	return BuiltinRules
}

// ListBuiltinRules returns a list of all built-in rule files
func ListBuiltinRules() ([]string, error) {
	entries, err := BuiltinRules.ReadDir("internal/builtin")
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && len(entry.Name()) > 5 && entry.Name()[len(entry.Name())-5:] == ".yaml" {
			files = append(files, "internal/builtin/"+entry.Name())
		}
	}

	return files, nil
}
