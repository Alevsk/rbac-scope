package renderer

import (
	"context"
	"testing"
)

func TestKustomizeRenderer(t *testing.T) {
	// Create test files content
	kustomizationContent := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- role.yaml`)

	roleContent := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]`)

	// Create renderer
	r := NewKustomizeRenderer(DefaultOptions())

	// Add files to the renderer
	if err := r.AddFile("role.yaml", roleContent); err != nil {
		t.Fatalf("failed to add role.yaml: %v", err)
	}

	// Add kustomization file
	if err := r.AddFile("kustomization.yaml", kustomizationContent); err != nil {
		t.Fatalf("failed to add kustomization.yaml: %v", err)
	}

	// Render
	result, err := r.Render(context.Background(), kustomizationContent)
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
