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
