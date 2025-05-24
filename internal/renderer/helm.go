package renderer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
)

// HelmRenderer implements Renderer for Helm charts
type HelmRenderer struct {
	opts *Options
}

// NewHelmRenderer creates a new HelmRenderer
func NewHelmRenderer(opts *Options) *HelmRenderer {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &HelmRenderer{opts: opts}
}

// Validate checks if the input is a valid Helm chart
func (r *HelmRenderer) Validate(input []byte) error {
	// Create a temporary directory for the chart
	tempDir, err := os.MkdirTemp("", "helm-validate-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Write the input to a temporary file
	chartPath := filepath.Join(tempDir, "chart.tgz")
	if err := os.WriteFile(chartPath, input, 0644); err != nil {
		return fmt.Errorf("failed to write chart file: %w", err)
	}

	// Try to load the chart
	_, err = loader.Load(chartPath)
	if err != nil {
		return fmt.Errorf("invalid helm chart: %w", err)
	}

	return nil
}

// Render processes a Helm chart and returns the rendered manifests
func (r *HelmRenderer) Render(ctx context.Context, input []byte) (*Result, error) {
	// Create a temporary directory for the chart
	tempDir, err := os.MkdirTemp("", "helm-render-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Write the input to a temporary file
	chartPath := filepath.Join(tempDir, "chart.tgz")
	if err := os.WriteFile(chartPath, input, 0644); err != nil {
		return nil, fmt.Errorf("failed to write chart file: %w", err)
	}

	// Load the chart
	chart, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart: %w", err)
	}

	// Load values from values.yaml if it exists
	values := chart.Values
	if chart.Values == nil {
		values = make(map[string]interface{})
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
		Strict:   true,
	}

	// Render templates
	rendered, err := renderer.Render(chart, valuesToRender)
	if err != nil {
		return nil, fmt.Errorf("failed to render templates: %w", err)
	}

	// Create result
	result := &Result{
		Manifests: make([]*Manifest, 0),
		Warnings:  make([]string, 0),
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
			manifestName := fmt.Sprintf("%s-%d", filepath.Base(name), i+1)

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
