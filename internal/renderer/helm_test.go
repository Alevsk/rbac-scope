package renderer

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestHelmRenderer_GetOptions(t *testing.T) {
	defaultOpts := DefaultOptions()
	r := NewHelmRenderer(nil)
	if !reflect.DeepEqual(r.GetOptions(), defaultOpts) {
		t.Errorf("GetOptions() for new renderer with nil opts = %v, want %v", r.GetOptions(), defaultOpts)
	}

	customOpts := &Options{OutputFormat: "json", IncludeMetadata: false}
	r = NewHelmRenderer(customOpts)
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

func TestHelmRenderer_RenderWithValues(t *testing.T) {
	tests := []struct {
		name           string
		valuesPath     string
		wantName       string
		wantManifests  int
		wantErr        bool
		wantErrMessage string
	}{
		{
			name:          "valid chart with values file",
			valuesPath:    "testdata/fixtures/chart/values.yaml",
			wantName:      "custom-name",
			wantManifests: 1,
		},
		{
			name:          "valid chart with external values file",
			valuesPath:    "testdata/fixtures/values/values.yaml",
			wantName:      "external-name",
			wantManifests: 1,
		},
		{
			name:           "invalid values file path",
			valuesPath:     "/nonexistent/values.yaml",
			wantErr:        true,
			wantErrMessage: "failed to read values file",
		},
		{
			name:          "no values file specified",
			valuesPath:    "",
			wantName:      "test", // Should use chart name as default
			wantManifests: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create renderer with values path
			r := NewHelmRenderer(&Options{Values: tt.valuesPath})

			// Add chart files
			files := map[string]string{
				"Chart.yaml":          "testdata/fixtures/chart/Chart.yaml",
				"templates/role.yaml": "testdata/fixtures/chart/templates/role.yaml",
			}

			// Only add values.yaml for test cases that should use it
			if tt.name == "valid chart with values file" {
				files["values.yaml"] = "testdata/fixtures/chart/values.yaml"
			}

			for name, path := range files {
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("Failed to read file %s: %v", path, err)
				}
				if err := r.AddFile(name, content); err != nil {
					t.Fatalf("Failed to add file %s: %v", name, err)
				}
			}

			// Render chart
			result, err := r.Render(context.Background(), nil)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.wantErrMessage) {
					t.Errorf("Expected error containing %q but got %q", tt.wantErrMessage, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify result
			if len(result.Manifests) != tt.wantManifests {
				t.Errorf("Expected %d manifests but got %d", tt.wantManifests, len(result.Manifests))
			}

			// Check if the role name was properly templated
			if len(result.Manifests) > 0 {
				manifest := result.Manifests[0]
				metadata, ok := manifest.Content["metadata"].(map[string]interface{})
				if !ok {
					t.Fatal("Expected metadata in manifest")
				}
				if name, ok := metadata["name"].(string); !ok || name != tt.wantName {
					t.Errorf("Expected role name %q but got %q", tt.wantName, name)
				}
			}
		})
	}
}

func TestHelmRenderer_ValidateSchema(t *testing.T) {
	validChartFiles := map[string][]byte{
		"Chart.yaml":          []byte("apiVersion: v2\nname: test\nversion: 0.1.0"),
		"templates/role.yaml": []byte("kind: Role\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  name: test-role"),
	}
	invalidChartFilesMissingChartYaml := map[string][]byte{
		"templates/role.yaml": []byte("kind: Role\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  name: test-role"),
	}

	tests := []struct {
		name    string
		files   map[string][]byte
		wantErr bool
	}{
		{
			name:    "valid chart schema",
			files:   validChartFiles,
			wantErr: false,
		},
		{
			name:    "invalid chart schema (missing Chart.yaml)",
			files:   invalidChartFilesMissingChartYaml,
			wantErr: true,
		},
		{
			name:    "empty files (should be invalid)",
			files:   map[string][]byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewHelmRenderer(DefaultOptions())
			for name, content := range tt.files {
				if err := r.AddFile(name, content); err != nil {
					t.Fatalf("Failed to add file %s: %v", name, err)
				}
			}
			// ValidateSchema calls Validate, which for HelmRenderer doesn't take input bytes but uses added files.
			// Passing nil as input to ValidateSchema as it's not used by Helm's Validate.
			err := r.ValidateSchema(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("HelmRenderer.ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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

func TestHelmRenderer_DefaultValues(t *testing.T) {
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
