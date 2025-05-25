package renderer

import (
	"context"
	"testing"
)

func TestYAMLRenderer(t *testing.T) {
	h := newTestHelper(t)
	ctx := context.Background()

	tests := []struct {
		name          string
		input         string
		opts          *Options
		wantManifests int
		wantWarnings  int
		wantErr       bool
	}{
		{
			name:          "valid cluster role",
			input:         "cluster-role.yaml",
			wantManifests: 2, // Role and RoleBinding
			wantWarnings:  0,
			wantErr:       false,
		},
		{
			name:          "valid role with json output",
			input:         "role.yaml",
			opts:          &Options{OutputFormat: "json"},
			wantManifests: 2, // Role and RoleBinding
			wantWarnings:  0,
			wantErr:       false,
		},
		{
			name:          "invalid yaml",
			input:         "invalid.yaml",
			wantManifests: 0,
			wantWarnings:  0,
			wantErr:       true,
		},
		{
			name:          "empty input",
			input:         "",
			wantManifests: 0,
			wantWarnings:  0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewYAMLRenderer()
			if tt.opts != nil {
				if err := r.SetOptions(tt.opts); err != nil {
					t.Fatalf("SetOptions() error = %v", err)
				}
			}

			var input []byte
			if tt.input != "" {
				input = h.readFixture(tt.input)
			}

			result, err := r.Render(ctx, input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Render() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if len(result.Manifests) != tt.wantManifests {
				t.Errorf("got %d manifests, want %d", len(result.Manifests), tt.wantManifests)
			}

			if len(result.Warnings) != tt.wantWarnings {
				t.Errorf("got %d warnings, want %d", len(result.Warnings), tt.wantWarnings)
			}

			// Validate manifest structure
			for _, m := range result.Manifests {
				if m.Name == "" {
					t.Error("manifest name is empty")
				}
				// Verify kind exists
				kind, ok := m.Content["kind"].(string)
				if !ok || kind == "" {
					t.Error("manifest kind is empty or not a string")
				}

				// Verify required fields based on kind
				switch kind {
				case "Role", "ClusterRole":
					if _, ok := m.Content["rules"]; !ok {
						t.Error("Role/ClusterRole manifest does not contain rules")
					}
				case "RoleBinding", "ClusterRoleBinding":
					if _, ok := m.Content["subjects"]; !ok {
						t.Error("RoleBinding/ClusterRoleBinding manifest does not contain subjects")
					}
					if _, ok := m.Content["roleRef"]; !ok {
						t.Error("RoleBinding/ClusterRoleBinding manifest does not contain roleRef")
					}
				}

				if r.opts.IncludeMetadata && m.Metadata == nil {
					t.Error("manifest metadata is nil when IncludeMetadata is true")
				}
			}
		})
	}
}

func TestYAMLRendererValidation(t *testing.T) {
	h := newTestHelper(t)

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errType error
	}{
		{
			name:    "valid cluster role",
			input:   "cluster-role.yaml",
			wantErr: false,
		},
		{
			name:    "invalid yaml",
			input:   "invalid.yaml",
			wantErr: true,
			errType: ErrInvalidFormat,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
			errType: ErrInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewYAMLRenderer()

			var input []byte
			if tt.input != "" {
				input = h.readFixture(tt.input)
			}

			err := r.ValidateSchema(input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errType != nil {
				if err != tt.errType && !isErrorType(err, tt.errType) {
					t.Errorf("ValidateSchema() error = %v, want error type %v", err, tt.errType)
				}
			}
		})
	}
}

func TestYAMLRendererOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name:    "valid yaml format",
			opts:    &Options{OutputFormat: "yaml"},
			wantErr: false,
		},
		{
			name:    "valid json format",
			opts:    &Options{OutputFormat: "json"},
			wantErr: false,
		},
		{
			name:    "invalid format",
			opts:    &Options{OutputFormat: "invalid"},
			wantErr: true,
		},
		{
			name:    "nil options",
			opts:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewYAMLRenderer()

			err := r.SetOptions(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetOptions() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				got := r.GetOptions()
				if got == nil {
					t.Error("GetOptions() returned nil")
				} else if got.OutputFormat != tt.opts.OutputFormat {
					t.Errorf("GetOptions().OutputFormat = %v, want %v",
						got.OutputFormat, tt.opts.OutputFormat)
				}
			}
		})
	}
}

func TestYAMLRenderer_Validate(t *testing.T) {
	h := newTestHelper(t)
	r := NewYAMLRenderer()

	valid := h.readFixture("role.yaml")
	if err := r.Validate(valid); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	invalid := h.readFixture("invalid.yaml")
	if err := r.Validate(invalid); err == nil {
		t.Fatal("expected error for invalid YAML")
	}

	if err := r.Validate([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

// isErrorType checks if err wraps target
func isErrorType(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		if unwrapped, ok := e.(interface{ Unwrap() error }); ok {
			e = unwrapped.Unwrap()
		} else {
			break
		}
	}
	return false
}
