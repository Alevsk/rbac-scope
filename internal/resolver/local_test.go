package resolver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

func TestLocalYAMLResolver_CanResolve(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()

	validFile := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte("key: value"), 0644); err != nil {
		t.Fatal(err)
	}

	nonYAMLFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(nonYAMLFile, []byte("text"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{
			name:   "valid yaml file",
			source: validFile,
			want:   true,
		},
		{
			name:   "non-yaml file",
			source: nonYAMLFile,
			want:   false,
		},
		{
			name:   "non-existent file",
			source: "nonexistent.yaml",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewLocalYAMLResolver(tt.source, nil)
			if got := r.CanResolve(tt.source); got != tt.want {
				t.Errorf("LocalYAMLResolver.CanResolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalYAMLResolver_Resolve(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		validate  bool
		wantErr   bool
		errType   error
		checkSize bool
	}{
		{
			name:      "valid yaml file",
			source:    "testdata/valid.yaml",
			validate:  true,
			wantErr:   false,
			checkSize: true,
		},
		{
			name:     "invalid yaml content",
			source:   "testdata/invalid.yaml",
			validate: true,
			wantErr:  true,
			errType:  renderer.ErrInvalidFormat,
		},
		{
			name:     "non-yaml file",
			source:   "testdata/invalid.txt",
			validate: true,
			wantErr:  true,
			errType:  renderer.ErrInvalidFormat,
		},
		{
			name:     "non-existent file",
			source:   "testdata/nonexistent.yaml",
			validate: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{ValidateYAML: tt.validate}
			r := NewLocalYAMLResolver(tt.source, opts)

			result, metadata, err := r.Resolve(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalYAMLResolver.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errType != nil && !strings.Contains(err.Error(), tt.errType.Error()) {
					t.Errorf("LocalYAMLResolver.Resolve() error = %v, want error containing %v", err, tt.errType)
				}
				return
			}

			if metadata == nil {
				t.Error("LocalYAMLResolver.Resolve() metadata is nil")
				return
			}

			if metadata.Type != SourceTypeFile {
				t.Errorf("LocalYAMLResolver.Resolve() type = %v, want %v", metadata.Type, SourceTypeFile)
			}

			if tt.checkSize {
				info, err := os.Stat(tt.source)
				if err != nil {
					t.Fatal(err)
				}
				if metadata.Size != info.Size() {
					t.Errorf("LocalYAMLResolver.Resolve() size = %v, want %v", metadata.Size, info.Size())
				}
			}

			// Verify we have valid manifests
			if result == nil {
				t.Error("LocalYAMLResolver.Resolve() result is nil")
				return
			}

			if len(result.Manifests) == 0 {
				t.Error("No manifests found in result")
				return
			}

			// Check that each manifest has content
			for i, manifest := range result.Manifests {
				if len(manifest.Raw) == 0 {
					t.Errorf("Manifest %d is empty", i)
				}
			}
		})
	}
}

func TestLocalYAMLResolver_ResolveWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	r := NewLocalYAMLResolver("testdata/valid.yaml", nil)
	_, _, err := r.Resolve(ctx)
	if err != context.Canceled {
		t.Errorf("LocalYAMLResolver.Resolve() error = %v, want %v", err, context.Canceled)
	}
}
