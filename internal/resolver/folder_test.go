package resolver

import (
	"context"
	"os"
	"path/filepath"
	"strings" // Added import
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer" // Added import
)

func TestFolderResolver_CanResolve(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "folder-resolver-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a temporary file
	tmpFile := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{
			name:   "valid directory",
			source: tmpDir,
			want:   true,
		},
		{
			name:   "file instead of directory",
			source: tmpFile,
			want:   false,
		},
		{
			name:   "non-existent path",
			source: "/path/does/not/exist",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewFolderResolver(tt.source, nil)
			if got := r.CanResolve(tt.source); got != tt.want {
				t.Errorf("FolderResolver.CanResolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolderResolver_Resolve(t *testing.T) {
	testDataDir := "testdata/folder"

	tests := []struct {
		name            string
		source          string
		followSymlinks  bool
		wantErr         bool
		wantFiles       int                                         // For YAML/mixed, this is number of YAML files. For Helm/Kustomize, usually 1 (the rendered result of the chart/kustomization)
		wantType        SourceType                                  // To check metadata
		wantRenderType  RendererType                                // To check metadata
		validateContent func(t *testing.T, result *renderer.Result) // Custom validation for Helm/Kustomize
	}{
		{
			name:           "valid directory with yaml files",
			source:         testDataDir,
			wantErr:        false,
			wantFiles:      3, // role1.yaml, role2.yml, and role3.yaml in subfolder
			wantType:       SourceTypeFolder,
			wantRenderType: RendererTypeYAML,
		},
		{
			name:           "non-existent directory",
			source:         "testdata/nonexistent",
			wantErr:        true,
			wantFiles:      0,
			wantType:       SourceTypeFolder, // Type is still folder, but resolve fails
			wantRenderType: RendererTypeYAML, // Default or N/A
		},
		{
			name:           "directory with mixed files (yaml default)",
			source:         "testdata/folder_mixed",
			wantErr:        false,
			wantFiles:      1, // Only role.yaml should be picked up by YAML renderer
			wantType:       SourceTypeFolder,
			wantRenderType: RendererTypeYAML,
		},
		{
			name:           "empty directory (yaml default)",
			source:         "testdata/folder_empty",
			wantErr:        true, // "no YAML files found"
			wantFiles:      0,
			wantType:       SourceTypeFolder,
			wantRenderType: RendererTypeYAML,
		},
		{
			name:           "helm chart directory",
			source:         "testdata/folder_helm_minimal",
			wantErr:        false,
			wantFiles:      1, // Helm renders to a single result (potentially multi-doc YAML)
			wantType:       SourceTypeFolder,
			wantRenderType: RendererTypeHelm,
			validateContent: func(t *testing.T, result *renderer.Result) {
				if result.Name != "mychart" {
					t.Errorf("Helm chart name mismatch: got %s, want mychart", result.Name)
				}
				// Check if a Role named like "*-helm-role" was rendered
				found := false
				for _, m := range result.Manifests {
					if strings.Contains(string(m.Raw), "kind: Role") && strings.Contains(string(m.Raw), "-helm-role") {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected Helm rendered Role not found in manifests")
				}
			},
		},
		{
			name:           "kustomize directory",
			source:         "testdata/folder_kustomize_minimal",
			wantErr:        false,
			wantFiles:      1, // Kustomize renders to a single result
			wantType:       SourceTypeFolder,
			wantRenderType: RendererTypeKustomize,
			validateContent: func(t *testing.T, result *renderer.Result) {
				// Check if the kustomized Role was rendered
				found := false
				for _, m := range result.Manifests {
					if strings.Contains(string(m.Raw), "kind: Role") && strings.Contains(string(m.Raw), "name: kustomized-role") {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected Kustomize rendered Role not found in manifests")
				}
			},
		},
		{
			name: "directory with unreadable yaml file",
			// Source will be a dynamically created temp dir
			wantErr: true, // Expect error from os.ReadFile
		},
		{
			name: "directory with invalid yaml content in yml file",
			// Source will be a dynamically created temp dir
			wantErr:        false,
			wantFiles:      1, // valid.yaml
			wantType:       SourceTypeFolder,
			wantRenderType: RendererTypeYAML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := tt.source
			var cleanupFunc func()

			if tt.name == "directory with unreadable yaml file" {
				tmpDir, err := os.MkdirTemp("", "unreadable-test")
				if err != nil {
					t.Fatalf("Failed to create temp dir for unreadable test: %v", err)
				}
				source = tmpDir
				cleanupFunc = func() { os.RemoveAll(tmpDir) }
				defer cleanupFunc()

				unreadableFile := filepath.Join(tmpDir, "unreadable.yaml")
				if err := os.WriteFile(unreadableFile, []byte("content"), 0644); err != nil {
					t.Fatalf("Failed to write unreadable.yaml: %v", err)
				}
				if err := os.Chmod(unreadableFile, 0000); err != nil {
					t.Fatalf("Failed to chmod unreadable.yaml to 0000: %v", err)
				}
				defer func() { // Ensure cleanup can happen
					if err := os.Chmod(unreadableFile, 0644); err != nil {
						t.Logf("Failed to change permissions back for unreadable.yaml: %v", err)
					}
				}()
			}

			if tt.name == "directory with invalid yaml content in yml file" {
				tmpDir, err := os.MkdirTemp("", "invalid-yml-test")
				if err != nil {
					t.Fatalf("Failed to create temp dir for invalid yml test: %v", err)
				}
				source = tmpDir
				cleanupFunc = func() { os.RemoveAll(tmpDir) }
				defer cleanupFunc()

				validFile := filepath.Join(tmpDir, "valid.yaml")
				if err := os.WriteFile(validFile, []byte("kind: Role\napiVersion: rbac.authorization.k8s.io/v1"), 0644); err != nil {
					t.Fatalf("Failed to write valid.yaml: %v", err)
				}
				invalidFile := filepath.Join(tmpDir, "invalid.yml")
				// This content is syntactically invalid YAML (duplicate key at the same level without sequence/map structure)
				// or simply something that `yaml.Unmarshal` would reject.
				// A truly syntactically invalid file:
				// if err := os.WriteFile(invalidFile, []byte("key: value\nkey: value"), 0644); err != nil {
				// Forcing a non-map/non-array at top level, which our strict renderer will reject,
				// but more importantly, making sure isValidYAML (if it's strict) might catch it,
				// or that buildWalkFunc handles the error from renderer.AddFile if ValidateYAML is on.
				// To ensure isValidYAML (from local.go, likely a simple unmarshal check) fails,
				// we need truly broken YAML syntax.
				// "foo: 'bar" was still not reliably failing the basic yaml.Unmarshal.
				// Using an unclosed sequence.
				if err := os.WriteFile(invalidFile, []byte("["), 0644); err != nil {
					t.Fatalf("Failed to write invalid.yml: %v", err)
				}
			}

			opts := &Options{
				ValidateYAML:   true, // Assuming true for most folder tests, can be part of struct if needed
				FollowSymlinks: tt.followSymlinks,
			}

			// Use the dynamically set source for specific tests
			r := NewFolderResolver(source, opts)
			result, metadata, err := r.Resolve(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("FolderResolver.Resolve() error = %v, wantErr %v for source %s", err, tt.wantErr, source)
				return
			}
			if tt.wantErr {
				return
			}

			if metadata == nil {
				t.Error("FolderResolver.Resolve() metadata is nil")
				return
			}
			if metadata.Type != tt.wantType {
				t.Errorf("FolderResolver.Resolve() metadata.Type = %v, want %v", metadata.Type, tt.wantType)
			}
			if metadata.RendererType != tt.wantRenderType {
				t.Errorf("FolderResolver.Resolve() metadata.RendererType = %v, want %v", metadata.RendererType, tt.wantRenderType)
			}

			if result == nil {
				t.Error("FolderResolver.Resolve() result is nil")
				return
			}

			// Count non-empty manifests if result is not nil
			actualManifestCount := 0
			if result.Manifests != nil {
				for _, m := range result.Manifests {
					if len(m.Raw) > 0 {
						actualManifestCount++
					}
				}
			}

			if actualManifestCount != tt.wantFiles {
				t.Errorf("FolderResolver.Resolve() found %d non-empty manifests, want %d", actualManifestCount, tt.wantFiles)
			}

			// Verify each manifest is valid YAML (if YAML type) or skip for Helm/Kustomize if specific validation is done
			if tt.wantRenderType == RendererTypeYAML {
				for i, manifest := range result.Manifests {
					if !isValidYAML(string(manifest.Raw)) { // isValidYAML is a helper from local_test.go, ensure it's accessible or reimplement
						t.Errorf("Manifest %d is not valid YAML:\n%s", i+1, string(manifest.Raw))
					}
				}
			}

			if tt.validateContent != nil {
				tt.validateContent(t, result)
			}
		})
	}
}

// Removed duplicate isValidYAML helper, will use the one from local.go

func TestFolderResolver_ResolveWithSymlinks(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "folder-resolver-symlink-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory with a YAML file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	yamlContent := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]`

	yamlFile := filepath.Join(subDir, "test.yaml")
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create YAML file: %v", err)
	}

	// Create a symlink to the subdirectory
	symlink := filepath.Join(tmpDir, "symlink")
	if err := os.Symlink(subDir, symlink); err != nil {
		t.Skipf("Skipping symlink test: %v", err)
		return
	}

	tests := []struct {
		name           string
		source         string
		followSymlinks bool
		wantErr        bool
		wantFiles      int
	}{
		{
			name:           "follow symlinks enabled",
			source:         tmpDir,
			followSymlinks: true,
			wantErr:        false,
			wantFiles:      2, // Original file and symlinked file
		},
		{
			name:           "follow symlinks disabled",
			source:         tmpDir,
			followSymlinks: false,
			wantErr:        false,
			wantFiles:      1, // Only original file
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{
				ValidateYAML:   true,
				FollowSymlinks: tt.followSymlinks,
			}

			r := NewFolderResolver(tt.source, opts)
			result, metadata, err := r.Resolve(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("FolderResolver.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if metadata == nil {
				t.Error("FolderResolver.Resolve() metadata is nil")
				return
			}
			if metadata.Type != SourceTypeFolder {
				t.Errorf("FolderResolver.Resolve() type = %v, want %v", metadata.Type, SourceTypeFolder)
			}

			if result == nil {
				t.Error("FolderResolver.Resolve() result is nil")
				return
			}

			foundFiles := 0
			for _, manifest := range result.Manifests {
				if len(manifest.Raw) > 0 {
					foundFiles++
				}
			}

			if foundFiles != tt.wantFiles {
				t.Errorf("FolderResolver.Resolve() found %d files, want %d", foundFiles, tt.wantFiles)
			}
		})
	}
}
