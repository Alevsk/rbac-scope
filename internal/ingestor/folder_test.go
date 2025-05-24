package ingestor

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		name           string
		source         string
		followSymlinks bool
		wantErr        bool
		wantFiles      int
	}{
		{
			name:      "valid directory with yaml files",
			source:    testDataDir,
			wantErr:   false,
			wantFiles: 3, // role1.yaml, role2.yml, and role3.yaml in subfolder
		},
		{
			name:      "non-existent directory",
			source:    "testdata/nonexistent",
			wantErr:   true,
			wantFiles: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{
				ValidateYAML:   true,
				FollowSymlinks: tt.followSymlinks,
				MaxConcurrency: 4,
			}

			r := NewFolderResolver(tt.source, opts)
			reader, metadata, err := r.Resolve(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("FolderResolver.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			defer reader.Close()

			if metadata == nil {
				t.Error("FolderResolver.Resolve() metadata is nil")
				return
			}
			if metadata.Type != SourceTypeFolder {
				t.Errorf("FolderResolver.Resolve() type = %v, want %v", metadata.Type, SourceTypeFolder)
			}

			// Read all content
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("Failed to read content: %v", err)
				return
			}

			// Count YAML documents by separator
			docs := strings.Split(string(content), "\n---\n")
			if len(docs) != tt.wantFiles {
				t.Errorf("FolderResolver.Resolve() found %d files, want %d", len(docs), tt.wantFiles)
			}

			// Verify each document is valid YAML
			for i, doc := range docs {
				if !isValidYAML(doc) {
					t.Errorf("Document %d is not valid YAML:\n%s", i+1, doc)
				}
			}
		})
	}
}

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
				MaxConcurrency: 4,
			}

			r := NewFolderResolver(tt.source, opts)
			reader, metadata, err := r.Resolve(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("FolderResolver.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			defer reader.Close()

			if metadata == nil {
				t.Error("FolderResolver.Resolve() metadata is nil")
				return
			}
			if metadata.Type != SourceTypeFolder {
				t.Errorf("FolderResolver.Resolve() type = %v, want %v", metadata.Type, SourceTypeFolder)
			}

			content, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("Failed to read content: %v", err)
				return
			}

			docs := strings.Split(string(content), "\n---\n")
			foundFiles := 0
			for _, doc := range docs {
				if strings.TrimSpace(doc) != "" {
					foundFiles++
				}
			}

			if foundFiles != tt.wantFiles {
				t.Errorf("FolderResolver.Resolve() found %d files, want %d", foundFiles, tt.wantFiles)
			}
		})
	}
}
