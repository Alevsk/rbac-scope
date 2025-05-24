package ingestor

import (
	"context"
	"testing"
	"time"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := New(nil)
			ctx := context.Background()

			result, err := i.Ingest(ctx, tt.source)

			if (err != nil) != tt.wantErr {
				t.Errorf("Ingest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.errType.Error() {
				t.Errorf("Ingest() error message = %v, want %v", err, tt.errType)
				return
			}

			if !tt.wantErr {
				if result == nil {
					t.Error("Ingest() result is nil, want non-nil")
					return
				}

				if !result.Success {
					t.Error("Ingest() success = false, want true")
				}

				if time.Now().Unix()-result.Timestamp > 5 {
					t.Error("Ingest() timestamp is too old")
				}
			}
		})
	}
}
