package renderer

import (
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// YAMLRenderer implements the Renderer interface for YAML/JSON files
type YAMLRenderer struct {
	opts *Options
}

// NewYAMLRenderer creates a new YAMLRenderer with default options
func NewYAMLRenderer() *YAMLRenderer {
	return &YAMLRenderer{
		opts: DefaultOptions(),
	}
}

// Render processes YAML input and returns rendered RBAC manifests
func (r *YAMLRenderer) Render(ctx context.Context, input []byte) (*Result, error) {
	if err := r.Validate(input); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	hash := sha512.Sum512(input)
	version := fmt.Sprintf("sha512:%x", hash)

	result := &Result{
		Name:      "",
		Version:   version,
		Manifests: make([]*Manifest, 0),
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(input)))
	docNum := 0

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var obj map[string]interface{}
		err := decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("failed to parse document %d: %v", docNum+1, err))
			continue
		}

		docNum++

		// Skip empty documents
		if len(obj) == 0 {
			continue
		}

		// Get name from metadata if available
		var name string
		if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
			if n, ok := metadata["name"].(string); ok {
				name = n
			}
		}

		// If no name found, generate one based on document number
		if name == "" {
			name = fmt.Sprintf("document-%d", docNum+1)
		}

		// Re-encode the document based on output format
		var raw []byte
		if r.opts.OutputFormat == "json" {
			raw, err = yaml.Marshal(obj)
			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("document %d: failed to encode as JSON: %v", docNum, err))
				continue
			}
		} else {
			raw, err = yaml.Marshal(obj)
			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("document %d: failed to encode as YAML: %v", docNum, err))
				continue
			}
		}

		manifest := &Manifest{
			Name:    name,
			Content: obj,
			Raw:     raw,
		}

		if r.opts.IncludeMetadata {
			manifest.Metadata = map[string]interface{}{
				"docNum": docNum + 1,
			}
		}

		result.Manifests = append(result.Manifests, manifest)
	}

	return result, nil
}

// Validate checks if the input is valid YAML
func (r *YAMLRenderer) Validate(input []byte) error {
	if len(input) == 0 {
		return ErrInvalidInput
	}

	// Basic YAML syntax validation
	var obj interface{}
	decoder := yaml.NewDecoder(strings.NewReader(string(input)))
	docCount := 0

	for {
		err := decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidFormat, err)
		}

		// Ensure we have a valid YAML structure (map or array)
		switch v := obj.(type) {
		case map[string]interface{}, []interface{}:
			// Valid YAML structure
			docCount++
		default:
			return fmt.Errorf("%w: document must be a YAML map or array, got %T", ErrInvalidFormat, v)
		}
	}

	// Ensure we found at least one document
	if docCount == 0 {
		return fmt.Errorf("%w: no valid YAML documents found", ErrInvalidFormat)
	}

	return nil
}

// ValidateSchema performs detailed validation of YAML schema
func (r *YAMLRenderer) ValidateSchema(input []byte) error {
	if err := r.Validate(input); err != nil {
		return err
	}

	// Split and validate each document
	decoder := yaml.NewDecoder(strings.NewReader(string(input)))
	docNum := 0

	for {
		var obj map[string]interface{}
		err := decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("document %d: %w", docNum+1, ErrValidationFailed)
		}

		docNum++

		// Skip empty documents
		if len(obj) == 0 {
			continue
		}

		// Validate required fields
		requiredFields := []string{"apiVersion", "kind", "metadata"}
		for _, field := range requiredFields {
			if _, ok := obj[field]; !ok {
				return fmt.Errorf("document %d: missing required field '%s': %w",
					docNum, field, ErrValidationFailed)
			}
		}

		// Validate metadata structure
		metadata, ok := obj["metadata"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("document %d: invalid metadata structure: %w",
				docNum, ErrValidationFailed)
		}

		if _, ok := metadata["name"].(string); !ok {
			return fmt.Errorf("document %d: missing or invalid metadata.name: %w",
				docNum, ErrValidationFailed)
		}
	}

	return nil
}

// SetOptions configures the renderer with the provided options
func (r *YAMLRenderer) SetOptions(opts *Options) error {
	if opts == nil {
		return ErrInvalidInput
	}

	// Validate output format
	switch opts.OutputFormat {
	case "yaml", "json":
		// Valid formats
	default:
		return fmt.Errorf("%w: unsupported output format: %s", ErrInvalidFormat, opts.OutputFormat)
	}

	r.opts = opts
	return nil
}

// GetOptions returns the current renderer options
func (r *YAMLRenderer) GetOptions() *Options {
	return r.opts
}

// AddFile adds a file to the renderer's context
func (r *YAMLRenderer) AddFile(name string, content []byte) error {
	// YAMLRenderer doesn't need additional files
	return nil
}
