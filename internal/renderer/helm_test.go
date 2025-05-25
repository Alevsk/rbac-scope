package renderer

import (
	"context"
	"testing"
)

func TestHelmRenderer(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string][]byte
		opts    *Options
		wantErr bool
	}{
		{
			name: "valid chart",
			files: map[string][]byte{
				"Chart.yaml": []byte(`apiVersion: v2
name: test-chart
version: 0.1.0`),
				"templates/role.yaml": []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]`),
			},
			opts:    DefaultOptions(),
			wantErr: false,
		},
		{
			name:    "invalid chart",
			files:   map[string][]byte{"invalid.yaml": []byte("not a helm chart")},
			opts:    DefaultOptions(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create renderer
			r := NewHelmRenderer(tt.opts)

			// Add files to the renderer
			for name, content := range tt.files {
				if err := r.AddFile(name, content); err != nil {
					t.Fatalf("failed to add file %s: %v", name, err)
				}
			}

			// Test validation
			err := r.Validate(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("HelmRenderer.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test rendering
			result, err := r.Render(context.Background(), nil)
			if err != nil {
				t.Fatalf("HelmRenderer.Render() error = %v", err)
			}

			// Validate result
			if result == nil {
				t.Fatal("HelmRenderer.Render() result is nil")
			}

			if len(result.Manifests) == 0 {
				t.Error("HelmRenderer.Render() no manifests returned")
			}

			// Validate manifests
			for _, m := range result.Manifests {
				if m.Name == "" {
					t.Error("manifest name is empty")
				}

				if m.Content == nil {
					t.Error("manifest content is nil")
				}

				if len(m.Raw) == 0 {
					t.Error("manifest raw content is empty")
				}

				if r.opts.IncludeMetadata {
					if m.Metadata == nil {
						t.Error("manifest metadata is nil when IncludeMetadata is true")
					}
					if _, ok := m.Metadata["template"]; !ok {
						t.Error("manifest metadata missing template name")
					}
					if _, ok := m.Metadata["docNum"]; !ok {
						t.Error("manifest metadata missing document number")
					}
				}
			}
		})
	}
}

func TestHelmRendererWithValues(t *testing.T) {
	// Create test files
	files := map[string][]byte{
		"Chart.yaml": []byte(`apiVersion: v2
name: test-chart
version: 0.1.0`),
		"values.yaml": []byte(`rbac:
  name: test-role
  rules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list"]`),
		"templates/role.yaml": []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Values.rbac.name }}
rules:
{{- toYaml .Values.rbac.rules | nindent 2 }}`),
	}

	// Create renderer
	r := NewHelmRenderer(DefaultOptions())

	// Add files to the renderer
	for name, content := range files {
		if err := r.AddFile(name, content); err != nil {
			t.Fatalf("failed to add file %s: %v", name, err)
		}
	}

	// Test rendering
	result, err := r.Render(context.Background(), nil)
	if err != nil {
		t.Fatalf("HelmRenderer.Render() error = %v", err)
	}

	// Validate result
	if len(result.Manifests) != 1 {
		t.Errorf("expected 1 manifest, got %d", len(result.Manifests))
	}

	// Validate manifest content
	m := result.Manifests[0]
	content := m.Content

	// Check kind
	kind, ok := content["kind"].(string)
	if !ok || kind != "Role" {
		t.Errorf("expected kind=Role, got %v", content["kind"])
	}

	// Check name
	metadata, ok := content["metadata"].(map[string]interface{})
	if !ok {
		t.Error("metadata not found")
	} else {
		name, ok := metadata["name"].(string)
		if !ok || name != "test-role" {
			t.Errorf("expected name=test-role, got %v", metadata["name"])
		}
	}

	// Check rules
	rules, ok := content["rules"].([]interface{})
	if !ok {
		t.Error("rules not found")
	} else if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
}

func TestHelmRenderer_AddFileErrors(t *testing.T) {
	r := NewHelmRenderer(DefaultOptions())

	if err := r.AddFile("", []byte("content")); err == nil {
		t.Error("expected error for empty file name")
	}

	if err := r.AddFile("file.yaml", nil); err == nil {
		t.Error("expected error for nil file content")
	}
}

func TestHelmRenderer_SetOptionsNil(t *testing.T) {
	r := NewHelmRenderer(DefaultOptions())
	if err := r.SetOptions(nil); err == nil {
		t.Fatal("expected error when setting nil options")
	}
}
