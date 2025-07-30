// Package version provides build and version information for Spotter
package version

import (
	"fmt"
	"runtime"
)

// Build information. These values are set via ldflags during build.
var (
	// Version is the semantic version of the build
	Version = "dev"
	
	// CommitHash is the git commit hash of the build
	CommitHash = "unknown"
	
	// BuildDate is the date when the binary was built
	BuildDate = "unknown"
	
	// GoVersion is the Go version used to build the binary
	GoVersion = "unknown"
)

// Info represents version and build information
type Info struct {
	Version    string `json:"version"`
	CommitHash string `json:"commit_hash"`
	BuildDate  string `json:"build_date"`
	GoVersion  string `json:"go_version"`
	Platform   string `json:"platform"`
}

// Get returns the version information
func Get() Info {
	return Info{
		Version:    Version,
		CommitHash: CommitHash,
		BuildDate:  BuildDate,
		GoVersion:  GoVersion,
		Platform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns a formatted version string
func (i Info) String() string {
	return fmt.Sprintf("Spotter %s (commit: %s, built: %s, go: %s, platform: %s)",
		i.Version, i.CommitHash, i.BuildDate, i.GoVersion, i.Platform)
}

// Short returns a short version string
func (i Info) Short() string {
	return fmt.Sprintf("Spotter %s", i.Version)
}

// GetVersion returns just the version string
func GetVersion() string {
	return Version
}

// GetCommitHash returns just the commit hash
func GetCommitHash() string {
	return CommitHash
}

// GetBuildDate returns just the build date
func GetBuildDate() string {
	return BuildDate
}

// GetGoVersion returns just the Go version
func GetGoVersion() string {
	return GoVersion
}

// GetPlatform returns the platform information
func GetPlatform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// IsDevBuild returns true if this is a development build
func IsDevBuild() bool {
	return Version == "dev" || CommitHash == "unknown"
}