package resolver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectRendererType(t *testing.T) {
	tests := []struct {
		name        string
		dirPath     string
		wantType    RendererType
		wantErr     bool
		errContains string
	}{
		{
			name:     "detect helm chart",
			dirPath:  filepath.Join("testdata", "fixtures", "helm_yaml"),
			wantType: RendererTypeHelm,
		},
		{
			name:     "detect helm chart with yml extension",
			dirPath:  filepath.Join("testdata", "fixtures", "helm_yml"),
			wantType: RendererTypeHelm,
		},
		{
			name:     "detect kustomize",
			dirPath:  filepath.Join("testdata", "fixtures", "kustomize_yaml"),
			wantType: RendererTypeKustomize,
		},
		{
			name:     "detect kustomize with yml extension",
			dirPath:  filepath.Join("testdata", "fixtures", "kustomize_yml"),
			wantType: RendererTypeKustomize,
		},
		{
			name:     "fallback to yaml",
			dirPath:  filepath.Join("testdata", "fixtures", "yaml"),
			wantType: RendererTypeYAML,
		},
		{
			name:     "fallback to yaml",
			dirPath:  filepath.Join("testdata", "fixtures", "yml"),
			wantType: RendererTypeYAML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, err := DetectRendererType(tt.dirPath)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantType, gotType)
		})
	}
}

func TestGetRendererForType(t *testing.T) {
	tests := []struct {
		name         string
		rendererType RendererType
		opts         *Options
		wantErr      bool
		errContains  string
	}{
		{
			name:         "yaml renderer",
			rendererType: RendererTypeYAML,
			opts:         DefaultOptions(),
		},
		{
			name:         "helm renderer",
			rendererType: RendererTypeHelm,
			opts:         DefaultOptions(),
		},
		{
			name:         "kustomize renderer",
			rendererType: RendererTypeKustomize,
			opts:         nil,
		},
		{
			name:         "unknown renderer",
			rendererType: RendererType(999),
			opts:         nil,
			wantErr:      true,
			errContains:  "unknown renderer type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renderer, err := GetRendererForType(tt.rendererType, tt.opts)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, renderer)
		})
	}
}
