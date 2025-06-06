package renderer

import (
	"context"
	"reflect"
	"testing"
)

func TestKustomizeRenderer_GetOptions(t *testing.T) {
	defaultOpts := DefaultOptions()
	r := NewKustomizeRenderer(nil)
	if !reflect.DeepEqual(r.GetOptions(), defaultOpts) {
		t.Errorf("GetOptions() for new renderer with nil opts = %v, want %v", r.GetOptions(), defaultOpts)
	}

	customOpts := &Options{OutputFormat: "json", IncludeMetadata: false}
	r = NewKustomizeRenderer(customOpts)
	if !reflect.DeepEqual(r.GetOptions(), customOpts) {
		t.Errorf("GetOptions() for new renderer with custom opts = %v, want %v", r.GetOptions(), customOpts)
	}

	setOpts := &Options{OutputFormat: "yaml", IncludeMetadata: true, ValidateOutput: false}
	err := r.SetOptions(setOpts)
	if err != nil {
		t.Fatalf("SetOptions() returned error: %v", err)
	}
	if !reflect.DeepEqual(r.GetOptions(), setOpts) {
		t.Errorf("GetOptions() after SetOptions = %v, want %v", r.GetOptions(), setOpts)
	}
}

func TestKustomizeRenderer_ValidateSchema(t *testing.T) {
	validKustomization := []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- role.yaml")
	invalidNotKustomization := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test-cm")
	invalidYAML := []byte("this: is: not: valid: yaml")

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid kustomization schema",
			input:   validKustomization,
			wantErr: false,
		},
		{
			name:    "invalid - not a kustomization kind",
			input:   invalidNotKustomization,
			wantErr: true,
		},
		{
			name:    "invalid - malformed yaml",
			input:   invalidYAML,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewKustomizeRenderer(DefaultOptions())
			err := r.ValidateSchema(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("KustomizeRenderer.ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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

func TestKustomizeRenderer_Validate(t *testing.T) {
	r := NewKustomizeRenderer(DefaultOptions())

	valid := []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n")
	if err := r.Validate(valid); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	invalid := []byte("kind: NotKustomize")
	if err := r.Validate(invalid); err == nil {
		t.Fatal("expected error for invalid kustomization")
	}
}

func TestKustomizeRenderer_AddFileErrors(t *testing.T) {
	r := NewKustomizeRenderer(DefaultOptions())

	if err := r.AddFile("", []byte("data")); err == nil {
		t.Error("expected error for empty file name")
	}

	if err := r.AddFile("file.yaml", nil); err == nil {
		t.Error("expected error for nil content")
	}
}

func TestKustomizeRenderer_SetOptionsNil(t *testing.T) {
	r := NewKustomizeRenderer(DefaultOptions())
	if err := r.SetOptions(nil); err == nil {
		t.Fatal("expected error when options are nil")
	}

	// Test setting valid options
	validOpts := &Options{OutputFormat: "json", IncludeMetadata: false, ValidateOutput: true}
	if err := r.SetOptions(validOpts); err != nil {
		t.Errorf("SetOptions() with valid opts returned error: %v", err)
	}
	retrievedOpts := r.GetOptions()
	if !reflect.DeepEqual(retrievedOpts, validOpts) {
		t.Errorf("GetOptions() after SetOptions = %v, want %v", retrievedOpts, validOpts)
	}

	// Ensure default options are different from what we set if possible, then set back
	if !reflect.DeepEqual(DefaultOptions(), validOpts) {
		if err := r.SetOptions(DefaultOptions()); err != nil {
			t.Errorf("SetOptions() with default opts returned error: %v", err)
		}
		if !reflect.DeepEqual(r.GetOptions(), DefaultOptions()) {
			t.Errorf("GetOptions() after resetting to default = %v, want %v", r.GetOptions(), DefaultOptions())
		}
	}
}
