package renderer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"

	yaml "gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
)

// HelmRenderer implements Renderer for Helm charts
type HelmRenderer struct {
	opts  *Options
	files map[string][]byte // Map to store files where key is the file name and value is the content
	mux   sync.RWMutex      // Mutex to protect concurrent access to files map

}

// NewHelmRenderer creates a new HelmRenderer
func NewHelmRenderer(opts *Options) *HelmRenderer {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &HelmRenderer{
		opts:  opts,
		files: make(map[string][]byte),
	}
}

// SetOptions configures the renderer with the provided options
func (r *HelmRenderer) SetOptions(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("options cannot be nil")
	}
	r.opts = opts
	return nil
}

// GetOptions returns the current renderer options
func (r *HelmRenderer) GetOptions() *Options {
	return r.opts
}

// AddFile adds a file to the renderer's context
func (r *HelmRenderer) AddFile(name string, content []byte) error {
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

// ValidateSchema checks if the input matches the expected schema
func (r *HelmRenderer) ValidateSchema(input []byte) error {
	return r.Validate(input)
}

// Validate checks if the input is a valid Helm chart
func (r *HelmRenderer) Validate(input []byte) error {
	// Lock the files map for reading
	r.mux.RLock()
	defer r.mux.RUnlock()

	// Convert files map to BufferedFile slice
	files := make([]*loader.BufferedFile, 0, len(r.files))
	for name, content := range r.files {
		files = append(files, &loader.BufferedFile{Name: name, Data: content})
	}

	// Try to load the chart from memory
	_, err := loader.LoadFiles(files)
	if err != nil {
		return fmt.Errorf("invalid helm chart: %w", err)
	}

	return nil
}

// Render processes a Helm chart and returns the rendered manifests
func (r *HelmRenderer) Render(ctx context.Context, folder []byte) (*Result, error) {
	// Lock the files map for reading
	r.mux.RLock()
	defer r.mux.RUnlock()

	// Convert files map to BufferedFile slice
	files := make([]*loader.BufferedFile, 0, len(r.files))
	for name, content := range r.files {
		files = append(files, &loader.BufferedFile{Name: name, Data: content})
	}

	// Load the chart from memory
	chart, err := loader.LoadFiles(files)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart: %w", err)
	}

	values := make(map[string]interface{})
	if r.opts.Values != "" {
		// Parse values from the specified values file path
		valueBytes, err := os.ReadFile(r.opts.Values)
		if err != nil {
			return nil, fmt.Errorf("failed to read values file %s: %w", r.opts.Values, err)
		}

		if err := yaml.Unmarshal(valueBytes, &values); err != nil {
			return nil, fmt.Errorf("failed to parse values file %s: %w", r.opts.Values, err)
		}
	} else if chart.Values != nil {
		// Load values from values.yaml if it exists
		values = chart.Values
	}

	// Create chart config
	options := chartutil.ReleaseOptions{
		Name:      chart.Name(),
		Namespace: "default",
		Revision:  1,
		IsInstall: true,
	}

	// Create chart values
	valuesToRender, err := chartutil.ToRenderValues(chart, values, options, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create chart values: %w", err)
	}

	// Create renderer
	renderer := engine.Engine{
		LintMode: false,
		Strict:   false,
	}
	// Render templates
	rendered, err := renderer.Render(chart, valuesToRender)
	if err != nil {
		return nil, fmt.Errorf("failed to render templates: %w", err)
	}

	// Create result
	result := &Result{
		Name:      chart.Name(),
		Version:   chart.Metadata.Version,
		Manifests: make([]*Manifest, 0),
		Warnings:  make([]string, 0),
		Extra:     make(map[string]interface{}),
	}

	result.Extra["helm"] = map[string]interface{}{
		"description": chart.Metadata.Description,
		"keywords":    chart.Metadata.Keywords,
		"home":        chart.Metadata.Home,
		"icon":        chart.Metadata.Icon,
		"kubeVersion": chart.Metadata.KubeVersion,
		"maintainers": chart.Metadata.Maintainers,
		"sources":     chart.Metadata.Sources,
	}

	// Process each rendered template
	for name, content := range rendered {
		if content == "" {
			continue
		}

		// Parse the rendered YAML
		decoder := yaml.NewDecoder(bytes.NewReader([]byte(content)))
		var docs []map[string]interface{}

		for {
			var doc map[string]interface{}
			if err := decoder.Decode(&doc); err != nil {
				break
			}
			docs = append(docs, doc)
		}

		// Create manifest for each document
		for i, doc := range docs {
			manifestName := fmt.Sprintf("%s-%d", name, i+1)

			// Re-encode as YAML
			raw, err := yaml.Marshal(doc)
			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("failed to encode manifest %s: %v", manifestName, err))
				continue
			}

			manifest := &Manifest{
				Name:    manifestName,
				Content: doc,
				Raw:     raw,
			}

			if r.opts.IncludeMetadata {
				manifest.Metadata = map[string]interface{}{
					"template": name,
					"docNum":   i + 1,
				}
			}

			result.Manifests = append(result.Manifests, manifest)
		}
	}

	return result, nil
}
