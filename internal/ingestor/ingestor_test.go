package ingestor

import (
	"context"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
		want *Options
	}{
		{
			name: "nil options should use defaults",
			opts: nil,
			want: DefaultOptions(),
		},
		{
			name: "custom options should be preserved",
			opts: &Options{
				MaxConcurrency: 8,
				FollowSymlinks: true,
				ValidateYAML:   false,
			},
			want: &Options{
				MaxConcurrency: 8,
				FollowSymlinks: true,
				ValidateYAML:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.opts)
			if got.opts.MaxConcurrency != tt.want.MaxConcurrency {
				t.Errorf("MaxConcurrency = %v, want %v", got.opts.MaxConcurrency, tt.want.MaxConcurrency)
			}
			if got.opts.FollowSymlinks != tt.want.FollowSymlinks {
				t.Errorf("FollowSymlinks = %v, want %v", got.opts.FollowSymlinks, tt.want.FollowSymlinks)
			}
			if got.opts.ValidateYAML != tt.want.ValidateYAML {
				t.Errorf("ValidateYAML = %v, want %v", got.opts.ValidateYAML, tt.want.ValidateYAML)
			}
		})
	}
}

func TestIngest(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantErr bool
		errType error
	}{
		{
			name:    "empty source should return error",
			source:  "",
			wantErr: true,
			errType: ErrInvalidSource,
		},
		{
			name:    "valid yaml file should succeed",
			source:  "testdata/valid.yaml",
			wantErr: false,
			errType: nil,
		},
		{
			name:    "resolver factory error for non-yaml local file",
			source:  "testdata/resolver_error.txt",
			wantErr: true,
			// Error will be from resolver.ResolverFactory, specific message depends on factory logic
			// e.g., "no suitable resolver found for source: testdata/resolver_error.txt"
			// or "URL does not point to a YAML file" if it were a URL.
			// For now, just check wantErr is true. We can refine errType later if needed.
		},
		{
			name:    "identity extractor error (skipped due to StrictParsing=false)",
			source:  "testdata/identity_extract_error.yaml",
			wantErr: false, // Extractor will skip malformed item if StrictParsing is false
		},
		{
			name:    "workload extractor error (skipped due to StrictParsing=false)",
			source:  "testdata/workload_extract_error.yaml",
			wantErr: false, // Extractor will skip malformed item if StrictParsing is false
		},
		{
			name:    "rbac extractor error (skipped due to StrictParsing=false)",
			source:  "testdata/rbac_extract_error.yaml",
			wantErr: false, // Extractor will skip malformed item if StrictParsing is false
		},
		{
			name:    "truly invalid yaml syntax",
			source:  "testdata/truly_invalid.yaml",
			wantErr: true, // Expecting a YAML parsing error from resolver or renderer
		},
		{
			name:    "formatter parse type error",
			source:  "testdata/valid.yaml", // Needs valid data to reach formatter stage
			wantErr: true,                  // Expecting "failed to parse formatter type: ..."
			// errType will be checked by string containment if not exact
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultOptions() // Start with default options for most tests
			if tt.name == "formatter parse type error" {
				opts.OutputFormat = "invalid-format"
			}

			i := New(opts)
			ctx := context.Background()

			result, err := i.Ingest(ctx, tt.source)

			if (err != nil) != tt.wantErr {
				t.Errorf("Ingest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expect an error and a specific type is provided, check it.
			// For some errors (like resolver factory or extractor errors), the exact message might be too brittle,
			// so we might only check if an error occurred (tt.wantErr = true).
			if tt.wantErr && tt.errType != nil {
				// For wrapped errors, direct comparison might fail. Consider strings.Contains or errors.Is.
				// For now, simple comparison for ErrInvalidSource.
				if err.Error() != tt.errType.Error() {
					t.Errorf("Ingest() error message = %q, want %q", err.Error(), tt.errType.Error())
					return
				}
			}

			if !tt.wantErr {
				if result == nil {
					t.Error("Ingest() result is nil, want non-nil")
					return
				}

				if !result.Success {
					t.Error("Ingest() success = false, want true")
				}

			}
		})
	}
}
