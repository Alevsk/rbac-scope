package renderer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHelmRenderer(t *testing.T) {
	// Create a test helper
	h := &testHelper{t: t}

	// Load test chart
	chartBytes := h.loadFixture("test-chart-0.1.0.tgz")

	tests := []struct {
		name    string
		input   []byte
		opts    *Options
		wantErr bool
	}{
		{
			name:    "valid chart",
			input:   chartBytes,
			opts:    DefaultOptions(),
			wantErr: false,
		},
		{
			name:    "invalid chart",
			input:   []byte("not a helm chart"),
			opts:    DefaultOptions(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create renderer
			r := NewHelmRenderer(tt.opts)

			// Test validation
			err := r.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HelmRenderer.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test rendering
			result, err := r.Render(context.Background(), tt.input)
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
		"Chart.yaml": []byte(`
apiVersion: v2
name: test-chart
version: 0.1.0
`),
		"values.yaml": []byte(`
rbac:
  name: test-role
  rules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list"]
`),
		"templates/role.yaml": []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Values.rbac.name }}
rules:
{{- toYaml .Values.rbac.rules | nindent 2 }}
`),
	}

	// Create temp dir
	tempDir, err := os.MkdirTemp("", "helm-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write files
	for name, content := range files {
		path := filepath.Join(tempDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatalf("failed to write file %s: %v", path, err)
		}
	}

	// Create renderer
	r := NewHelmRenderer(DefaultOptions())

	// Create a temporary chart directory
	chartDir := filepath.Join(tempDir, "chart")
	if err := os.MkdirAll(filepath.Join(chartDir, "templates"), 0755); err != nil {
		t.Fatalf("failed to create chart dir: %v", err)
	}

	// Write chart files
	for name, content := range files {
		path := filepath.Join(chartDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatalf("failed to write file %s: %v", path, err)
		}
	}

	// Package chart
	cmd := exec.Command("helm", "package", chartDir, "--destination", tempDir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to package chart: %v", err)
	}

	// Extract chart path from output
	chartPath := filepath.Join(tempDir, "test-chart-0.1.0.tgz")

	// Read chart
	chartBytes, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("failed to read chart: %v", err)
	}

	// Test rendering
	result, err := r.Render(context.Background(), chartBytes)
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
