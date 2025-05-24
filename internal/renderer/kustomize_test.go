package renderer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKustomizeRenderer(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "kustomize-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	files := map[string][]byte{
		"kustomization.yaml": []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- role.yaml`),
		"role.yaml": []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]`),
	}

	// Write test files
	for name, content := range files {
		path := filepath.Join(tempDir, name)
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatalf("failed to write file %s: %v", path, err)
		}
	}

	// Create renderer
	r := NewKustomizeRenderer(DefaultOptions())

	// Read kustomization directory
	input, err := os.ReadFile(filepath.Join(tempDir, "kustomization.yaml"))
	if err != nil {
		t.Fatalf("failed to read kustomization: %v", err)
	}

	// Render
	result, err := r.Render(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to render: %v", err)
	}

	// Validate result
	if len(result.Manifests) != 1 {
		t.Errorf("expected 1 manifest, got %d", len(result.Manifests))
	}

	manifest := result.Manifests[0]
	kind, ok := manifest.Content["kind"].(string)
	if !ok || kind != "Role" {
		t.Errorf("expected Role, got %v", manifest.Content["kind"])
	}

	metadata, ok := manifest.Content["metadata"].(map[string]interface{})
	if !ok {
		t.Error("metadata not found or invalid type")
		return
	}

	name, ok := metadata["name"].(string)
	if !ok || name != "test-role" {
		t.Errorf("expected test-role, got %v", metadata["name"])
	}
}
