package ingestor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

// RendererType represents the type of renderer to use
type RendererType int

const (
	// RendererTypeYAML is used for plain YAML files
	RendererTypeYAML RendererType = iota
	// RendererTypeHelm is used for Helm charts
	RendererTypeHelm
	// RendererTypeKustomize is used for Kustomize directories
	RendererTypeKustomize
)

// DetectRendererType determines which renderer to use based on the directory contents
func DetectRendererType(dirPath string) (RendererType, error) {
	// Check for Chart.yaml (Helm)
	chartPath := filepath.Join(dirPath, "Chart.yaml")
	if _, err := os.Stat(chartPath); err == nil {
		return RendererTypeHelm, nil
	}

	// Check for kustomization.yaml (Kustomize)
	kustomizePath := filepath.Join(dirPath, "kustomization.yaml")
	if _, err := os.Stat(kustomizePath); err == nil {
		return RendererTypeKustomize, nil
	}

	// Default to YAML renderer
	return RendererTypeYAML, nil
}

// GetRendererForType returns the appropriate renderer for the given type
func GetRendererForType(typ RendererType) (renderer.Renderer, error) {
	switch typ {
	case RendererTypeYAML:
		return renderer.NewYAMLRenderer(), nil
	case RendererTypeHelm:
		return renderer.NewHelmRenderer(nil), nil
	case RendererTypeKustomize:
		return renderer.NewKustomizeRenderer(nil), nil
	default:
		return nil, fmt.Errorf("unknown renderer type: %v", typ)
	}
}
