package resolver

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// testHelper provides common test utilities for resolvers
type testHelper struct {
	t *testing.T
}

// newTestHelper creates a new test helper
func newTestHelper(t *testing.T) *testHelper {
	return &testHelper{t: t}
}

// verifyResolverOutput checks the output of a resolver against expected values
func (h *testHelper) verifyResolverOutput(resolver SourceResolver, wantErr bool, wantType SourceType) {
	ctx := context.Background()
	reader, metadata, err := resolver.Resolve(ctx)
	if (err != nil) != wantErr {
		h.t.Errorf("Resolve() error = %v, wantErr %v", err, wantErr)
		return
	}
	if wantErr {
		return
	}

	defer reader.Close()

	if metadata == nil {
		h.t.Error("Resolve() metadata is nil")
		return
	}

	if metadata.Type != wantType {
		h.t.Errorf("Resolve() type = %v, want %v", metadata.Type, wantType)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		h.t.Errorf("Failed to read content: %v", err)
		return
	}

	if !isValidYAML(string(content)) {
		h.t.Error("Content is not valid YAML")
	}
}

// createTempDir creates a temporary directory with the given files
func (h *testHelper) createTempDir(files map[string]string) string {
	tmpDir, err := os.MkdirTemp("", "resolver-test-dir-")
	if err != nil {
		h.t.Fatalf("Failed to create temp dir: %v", err)
	}

	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			h.t.Fatalf("Failed to create directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			h.t.Fatalf("Failed to write file %s: %v", name, err)
		}
	}

	return tmpDir
}

// readFixture reads a test fixture file from testdata/fixtures
func (h *testHelper) readFixture(name string) string {
	content, err := os.ReadFile(filepath.Join("testdata", "fixtures", name))
	if err != nil {
		h.t.Fatalf("Failed to read fixture %s: %v", name, err)
	}
	return string(content)
}

// cleanupTemp removes a temporary file or directory
func (h *testHelper) cleanupTemp(path string) {
	if err := os.RemoveAll(path); err != nil {
		h.t.Errorf("Failed to cleanup %s: %v", path, err)
	}
}
