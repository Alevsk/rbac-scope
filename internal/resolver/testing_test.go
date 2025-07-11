package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alevsk/rbac-scope/internal/renderer"
)

type stubResolver struct {
	result *renderer.Result
	meta   *ResolverMetadata
	err    error
}

func (s stubResolver) CanResolve(string) bool { return true }
func (s stubResolver) Resolve(ctx context.Context) (*renderer.Result, *ResolverMetadata, error) {
	return s.result, s.meta, s.err
}

func TestHelperTempDirAndCleanup(t *testing.T) {
	h := newTestHelper(t)
	dir := h.createTempDir(map[string]string{"a.txt": "data"})
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); err != nil {
		t.Fatalf("file not created: %v", err)
	}
	h.cleanupTemp(dir)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir should be removed, err=%v", err)
	}
}

func TestHelperReadFixture(t *testing.T) {
	h := newTestHelper(t)
	content := h.readFixture("cluster-role.yaml")
	if len(content) == 0 {
		t.Fatal("fixture empty")
	}
}

func TestVerifyResolverOutput(t *testing.T) {
	h := newTestHelper(t)
	res := &renderer.Result{Manifests: []*renderer.Manifest{{Raw: []byte("kind: Pod")}}}
	meta := &ResolverMetadata{Type: SourceTypeFile}
	r := stubResolver{result: res, meta: meta}
	if got, _ := h.verifyResolverOutput(r, false, SourceTypeFile); got == nil {
		t.Fatal("expected result")
	}
	r.err = os.ErrNotExist
	if got, _ := h.verifyResolverOutput(r, true, SourceTypeFile); got != nil {
		t.Fatal("expected nil on error")
	}
}
