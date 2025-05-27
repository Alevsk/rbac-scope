package resolver

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

// rendererDefinition defines a renderer type and its identifiers
type rendererDefinition struct {
	Type        RendererType
	Identifiers []string
}

// DetectRendererType determines which renderer to use based on the directory contents
func DetectRendererType(dirPath string) (RendererType, error) {

	definitions := []rendererDefinition{
		{
			Type:        RendererTypeHelm,
			Identifiers: []string{"Chart.yaml", "Chart.yml"},
		},
		{
			Type:        RendererTypeKustomize,
			Identifiers: []string{"kustomization.yaml", "kustomization.yml"},
		},
	}

	for _, definition := range definitions {
		for _, identifier := range definition.Identifiers {
			filePath := filepath.Join(dirPath, identifier)
			fileInfo, err := os.Stat(filePath)

			if err == nil {
				if fileInfo.IsDir() {
					continue
				}
				return definition.Type, nil
			}

			if !os.IsNotExist(err) {
				return RendererTypeYAML, fmt.Errorf("error checking for %s: %w", filePath, err)
			}
		}
	}

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
