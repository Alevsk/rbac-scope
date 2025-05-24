package renderer

import (
	"os"
	"path/filepath"
	"testing"
)

// testHelper provides utilities for testing renderers
type testHelper struct {
	t *testing.T
}

// newTestHelper creates a new testHelper instance
func newTestHelper(t *testing.T) *testHelper {
	return &testHelper{t: t}
}

// readFixture reads a test fixture file from testdata directory
func (h *testHelper) readFixture(name string) []byte {
	path := filepath.Join("testdata", name)
	content, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return content
}

// createTempDir creates a temporary directory with the given files
func (h *testHelper) createTempDir(files map[string][]byte) string {
	tempDir, err := os.MkdirTemp("", "renderer-test-*")
	if err != nil {
		h.t.Fatalf("failed to create temp dir: %v", err)
	}

	for name, content := range files {
		path := filepath.Join(tempDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			h.t.Fatalf("failed to create dir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			h.t.Fatalf("failed to write file %s: %v", path, err)
		}
	}

	return tempDir
}

// cleanupTemp removes a temporary directory and its contents
func (h *testHelper) cleanupTemp(dir string) {
	if err := os.RemoveAll(dir); err != nil {
		h.t.Fatalf("failed to cleanup temp dir %s: %v", dir, err)
	}
}
