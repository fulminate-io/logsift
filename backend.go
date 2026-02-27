package logsift

import (
	"context"
	"sort"
	"sync"
)

// Backend is the interface every log provider implements.
// Each backend is responsible for:
//  1. Checking credential availability
//  2. Translating structured Query params into native query syntax
//  3. Returning normalized LogEntry structs (common field names)
//  4. Respecting context cancellation
//  5. Stopping at MaxRawEntries to bound memory usage
type Backend interface {
	// Search translates the query to native syntax, executes it, and returns
	// normalized log entries. Field normalization happens HERE — the reduction
	// pipeline receives a uniform schema regardless of provider.
	Search(ctx context.Context, creds *Credentials, q *Query) (*RawResults, error)

	// Available checks whether this backend has credentials configured.
	Available(creds *Credentials) bool

	// ListSources returns available log sources (log groups, indices, label values, etc.)
	// The prefix parameter filters results (empty = return all, up to 100).
	ListSources(ctx context.Context, creds *Credentials, prefix string) ([]SourceInfo, error)
}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Backend)
)

// Register adds a backend to the global registry. Called from backend init() functions.
func Register(name string, b Backend) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = b
}

// Get returns a backend by name.
func Get(name string) (Backend, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	b, ok := registry[name]
	return b, ok
}

// Available returns the names of backends that have credentials configured.
func Available(creds *Credentials) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var names []string
	for name, b := range registry {
		if b.Available(creds) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// RegisteredBackends returns all registered backend names (regardless of credential availability).
func RegisteredBackends() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var names []string
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
