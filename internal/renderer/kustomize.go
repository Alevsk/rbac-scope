package renderer

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	yaml "gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// KustomizeRenderer implements Renderer for Kustomize manifests
type KustomizeRenderer struct {
	opts  *Options
	files map[string][]byte // Map to store files where key is the file name and value is the content
	mux   sync.RWMutex      // Mutex to protect concurrent access to files map
}

// NewKustomizeRenderer creates a new KustomizeRenderer
func NewKustomizeRenderer(opts *Options) *KustomizeRenderer {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &KustomizeRenderer{
		opts:  opts,
		files: make(map[string][]byte),
	}
}

// Render processes a Kustomize directory and returns the rendered manifests
func (r *KustomizeRenderer) Render(ctx context.Context, input []byte) (*Result, error) {
	// Create an in-memory filesystem
	fs := filesys.MakeFsInMemory()

	// Parse input to get referenced files
	var kustomization struct {
		Kind      string   `yaml:"kind"`
		Resources []string `yaml:"resources"`
	}

	if err := yaml.Unmarshal(input, &kustomization); err != nil {
		return nil, fmt.Errorf("failed to parse kustomization: %w", err)
	}

	// Lock the files map for reading
	r.mux.RLock()
	defer r.mux.RUnlock()

	// Write the kustomization file to the in-memory filesystem
	if err := fs.WriteFile("/kustomization.yaml", input); err != nil {
		return nil, fmt.Errorf("failed to write kustomization: %w", err)
	}

	// Write all files from the map to the in-memory filesystem
	for name, content := range r.files {
		// Create parent directories if they don't exist
		dir := filepath.Dir("/" + name)
		if err := fs.MkdirAll(dir); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Write the file
		if err := fs.WriteFile("/"+name, content); err != nil {
			return nil, fmt.Errorf("failed to write file %s: %w", name, err)
		}
	}

	// Create kustomize builder
	k := krusty.MakeKustomizer(
		krusty.MakeDefaultOptions(),
	)

	// Build the resources
	resources, err := k.Run(fs, "/")
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

// AddFile adds a file to the renderer's context in a thread-safe manner
func (r *KustomizeRenderer) AddFile(name string, content []byte) error {
	if name == "" {
		return fmt.Errorf("file name cannot be empty")
	}
	if content == nil {
		return fmt.Errorf("file content cannot be nil")
	}
	r.mux.Lock()
	defer r.mux.Unlock()
	r.files[name] = content
	return nil
}
