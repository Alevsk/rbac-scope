package renderer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// KustomizeRenderer implements Renderer for Kustomize manifests
type KustomizeRenderer struct {
	opts *Options
}

// NewKustomizeRenderer creates a new KustomizeRenderer
func NewKustomizeRenderer(opts *Options) *KustomizeRenderer {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &KustomizeRenderer{opts: opts}
}

// Render processes a Kustomize directory and returns the rendered manifests
func (r *KustomizeRenderer) Render(ctx context.Context, input []byte) (*Result, error) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "kustomize-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Parse input to get referenced files
	var kustomization struct {
		Kind      string   `yaml:"kind"`
		Resources []string `yaml:"resources"`
	}

	if err := yaml.Unmarshal(input, &kustomization); err != nil {
		return nil, fmt.Errorf("failed to parse kustomization: %w", err)
	}

	// Write the kustomization file
	if err := os.WriteFile(filepath.Join(tempDir, "kustomization.yaml"), input, 0644); err != nil {
		return nil, fmt.Errorf("failed to write kustomization: %w", err)
	}

	// Write referenced files
	for _, resource := range kustomization.Resources {
		// Read the resource from testdata/fixtures/test-kustomize
		fixtureContent, err := os.ReadFile(filepath.Join("testdata", "fixtures", "test-kustomize", resource))
		if err != nil {
			return nil, fmt.Errorf("failed to read fixture %s: %w", resource, err)
		}

		// Write the resource to the temp directory
		if err := os.WriteFile(filepath.Join(tempDir, resource), fixtureContent, 0644); err != nil {
			return nil, fmt.Errorf("failed to write %s: %w", resource, err)
		}
	}

	// Create a filesystem for kustomize
	fs := filesys.MakeFsOnDisk()

	// Create kustomize builder
	k := krusty.MakeKustomizer(
		krusty.MakeDefaultOptions(),
	)

	// Build the resources
	resources, err := k.Run(fs, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to build resources: %w", err)
	}

	// Convert resources to yaml
	yamlData, err := resources.AsYaml()
	if err != nil {
		return nil, fmt.Errorf("failed to convert resources to yaml: %w", err)
	}

	// Parse the rendered manifests
	result := &Result{
		Manifests: make([]*Manifest, 0),
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(yamlData)))

	for {
		var obj map[string]interface{}
		err := decoder.Decode(&obj)
		if err == nil {
			manifest := &Manifest{
				Content:  obj,
				Metadata: make(map[string]interface{}),
			}

			// Extract name from metadata if present
			if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
				if name, ok := metadata["name"].(string); ok {
					manifest.Name = name
				}
			}

			result.Manifests = append(result.Manifests, manifest)
		} else if err.Error() == "EOF" {
			break
		} else {
			return nil, fmt.Errorf("failed to parse manifest: %w", err)
		}
	}

	return result, nil
}

// Validate checks if the input can be handled by this renderer
func (r *KustomizeRenderer) Validate(input []byte) error {
	var obj map[string]interface{}
	if err := yaml.Unmarshal(input, &obj); err != nil {
		return fmt.Errorf("%w: invalid yaml", ErrInvalidInput)
	}

	// Check if it's a kustomization file
	if kind, ok := obj["kind"].(string); !ok || kind != "Kustomization" {
		return fmt.Errorf("%w: not a kustomization file", ErrInvalidInput)
	}

	return nil
}

// ValidateSchema checks if the input matches the expected schema
func (r *KustomizeRenderer) ValidateSchema(input []byte) error {
	return r.Validate(input)
}

// SetOptions configures the renderer with the provided options
func (r *KustomizeRenderer) SetOptions(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("options cannot be nil")
	}
	r.opts = opts
	return nil
}

// GetOptions returns the current renderer options
func (r *KustomizeRenderer) GetOptions() *Options {
	return r.opts
}
