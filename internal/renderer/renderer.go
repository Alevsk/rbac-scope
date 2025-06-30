// Package renderer provides functionality for rendering RBAC manifests
// from various sources into a standardized format.
package renderer

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-scope/internal/types"
)

// Options contains configuration options for renderers
type Options struct {
	// ValidateOutput determines if the rendered output should be validated
	ValidateOutput bool
	// IncludeMetadata determines if metadata should be included in rendered output
	IncludeMetadata bool
	// OutputFormat specifies the desired output format (e.g., yaml, json)
	OutputFormat string
	// Values is a path to a values.yaml file used for rendering a helm chart
	Values string
}

// DefaultOptions returns a new Options with default values
func DefaultOptions() *Options {
	return &Options{
		ValidateOutput:  true,
		IncludeMetadata: true,
		OutputFormat:    "yaml",
		Values:          "",
	}
}

// Result contains the output of a render operation
// Result is an alias for types.Result
type Result = types.Result

// Manifest is an alias for types.Manifest
type Manifest = types.Manifest

// Error types for the renderer package
var (
	ErrInvalidInput     = fmt.Errorf("invalid input")
	ErrInvalidFormat    = fmt.Errorf("invalid format")
	ErrValidationFailed = fmt.Errorf("validation failed")
)

// Renderer defines the interface for RBAC manifest renderers.
// Implementations of this interface are responsible for converting input
// data into standardized RBAC manifests that can be analyzed by the system.
type Renderer interface {
	// Render processes the input data and returns rendered RBAC manifests.
	// The context can be used to cancel long-running render operations.
	// The input should be validated before calling Render.
	//
	// Returns:
	// - Result: Contains the rendered manifests and any non-fatal warnings
	// - error: Fatal errors that prevented rendering
	Render(ctx context.Context, input []byte) (*Result, error)

	// Validate checks if the input can be handled by this renderer.
	// This should be called before attempting to render the input.
	//
	// Returns:
	// - nil if the input is valid and can be rendered
	// - ErrInvalidInput if the input format is not supported
	// - ErrValidationFailed if the input fails schema validation
	Validate(input []byte) error

	// ValidateSchema checks if the input matches the expected schema.
	// This is separate from Validate to allow for more granular validation.
	//
	// Returns:
	// - nil if the input matches the expected schema
	// - ErrValidationFailed with details if validation fails
	ValidateSchema(input []byte) error

	// SetOptions configures the renderer with the provided options.
	// This can be called multiple times to update the configuration.
	// Invalid options will return an error and leave the configuration unchanged.
	SetOptions(opts *Options) error

	// GetOptions returns a copy of the current renderer options.
	// This allows inspection of the current configuration without
	// exposing internal state.
	GetOptions() *Options

	// AddFile adds a file to the renderer's context
	AddFile(name string, content []byte) error
}
