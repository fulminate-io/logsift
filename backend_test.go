package logsift

import (
	"context"
	"testing"
)

// mockBackend implements Backend for testing.
type mockBackend struct {
	available  bool
	searchFunc func(ctx context.Context, creds *Credentials, q *Query) (*RawResults, error)
	listFunc   func(ctx context.Context, creds *Credentials, prefix string) ([]SourceInfo, error)
}

func (b *mockBackend) Available(_ *Credentials) bool {
	return b.available
}

func (b *mockBackend) Search(ctx context.Context, creds *Credentials, q *Query) (*RawResults, error) {
	if b.searchFunc != nil {
		return b.searchFunc(ctx, creds, q)
	}
	return &RawResults{}, nil
}

func (b *mockBackend) ListSources(ctx context.Context, creds *Credentials, prefix string) ([]SourceInfo, error) {
	if b.listFunc != nil {
		return b.listFunc(ctx, creds, prefix)
	}
	return nil, nil
}

func TestRegistry(t *testing.T) {
	// Clean registry for test
	registryMu.Lock()
	origRegistry := registry
	registry = make(map[string]Backend)
	registryMu.Unlock()
	defer func() {
		registryMu.Lock()
		registry = origRegistry
		registryMu.Unlock()
	}()

	// Register a mock backend
	Register("test-provider", &mockBackend{available: true})

	// Get it back
	b, ok := Get("test-provider")
	if !ok {
		t.Fatal("expected to find test-provider")
	}
	if !b.Available(nil) {
		t.Error("expected backend to be available")
	}

	// Unknown provider
	_, ok = Get("unknown")
	if ok {
		t.Error("should not find unknown provider")
	}

	// Available backends
	creds := &Credentials{}
	available := Available(creds)
	if len(available) != 1 || available[0] != "test-provider" {
		t.Errorf("expected [test-provider], got %v", available)
	}

	// Registered backends
	registered := RegisteredBackends()
	if len(registered) != 1 || registered[0] != "test-provider" {
		t.Errorf("expected [test-provider], got %v", registered)
	}
}

func TestAvailableBackends_FiltersByCredentials(t *testing.T) {
	registryMu.Lock()
	origRegistry := registry
	registry = make(map[string]Backend)
	registryMu.Unlock()
	defer func() {
		registryMu.Lock()
		registry = origRegistry
		registryMu.Unlock()
	}()

	Register("available-provider", &mockBackend{available: true})
	Register("unavailable-provider", &mockBackend{available: false})

	creds := &Credentials{}
	available := Available(creds)

	if len(available) != 1 || available[0] != "available-provider" {
		t.Errorf("expected only available-provider, got %v", available)
	}
}
