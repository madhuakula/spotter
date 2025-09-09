package graphstore

import (
	"context"
	"time"

	"github.com/madhuakula/spotter/pkg/models"
)

// GraphStore defines the interface for the embedded graph database
type GraphStore interface {
	// Open opens the graph database at the specified path
	// Handles TTL check, locking, and Kuzu database initialization
	Open(path string) error

	// Close closes the graph database connection
	Close() error

	// EnsureSchema creates the required node and relationship tables
	EnsureSchema(ctx context.Context) error

	// UpsertFacts inserts or updates facts (nodes and relationships) in the graph
	UpsertFacts(ctx context.Context, facts *models.GraphFacts) error

	// RunCorrelations executes the specified correlation queries and returns findings
	RunCorrelations(ctx context.Context, correlationTypes []string) ([]models.AttackPathFinding, error)

	// Invalidate deletes the database directory (for --force-refresh)
	Invalidate() error

	// IsStale checks if the database is stale based on TTL
	IsStale(ttl time.Duration) (bool, error)

	// GetLastModified returns the last modification time of the database
	GetLastModified() (time.Time, error)
}

// CacheConfig represents configuration for the graph store cache
type CacheConfig struct {
	// CacheDir is the directory where the cache is stored
	CacheDir string

	// TTL is the time-to-live for cached data
	TTL time.Duration

	// NoCache disables caching (in-memory only)
	NoCache bool

	// ForceRefresh forces a cache refresh
	ForceRefresh bool

	// Target is the scan target (used for cache key generation)
	Target string
}

// LockManager handles file locking for concurrent access
type LockManager interface {
	// AcquireExclusiveLock acquires an exclusive lock for writing
	AcquireExclusiveLock(path string) error

	// AcquireSharedLock acquires a shared lock for reading
	AcquireSharedLock(path string) error

	// ReleaseLock releases the acquired lock
	ReleaseLock() error
}
