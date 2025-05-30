// Package extractor provides functionality to extract and analyze Kubernetes RBAC information
package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
	"github.com/alevsk/rbac-ops/internal/types"
)

// Options contains configuration options for extractors
type Options struct {
	// StrictParsing enables strict YAML parsing mode
	StrictParsing bool
	// IncludeMetadata includes additional metadata in extraction results
	IncludeMetadata bool
}

// DefaultOptions returns the default extractor options
func DefaultOptions() *Options {
	return &Options{
		StrictParsing:   false,
		IncludeMetadata: true,
	}
}

// Result represents the output of an extractor
// Result is an alias for types.ExtractedData
type Result = types.ExtractedData

// NewResult creates a new Result with initialized fields
func NewResult() *Result {
	return &Result{
		Metadata: make(map[string]interface{}),
		Data:     make(map[string]interface{}),
	}
}

// Error types for the extractor package
var (
	ErrInvalidInput    = fmt.Errorf("invalid input")
	ErrUnsupportedType = fmt.Errorf("unsupported resource type")
	ErrMissingMetadata = fmt.Errorf("missing required metadata")
	ErrExtractionError = fmt.Errorf("extraction failed")
)

// Extractor defines the interface for extracting information from Kubernetes resources
type Extractor interface {
	// Extract processes the manifests and returns structured data
	Extract(ctx context.Context, manifests []*renderer.Manifest) (*Result, error)
	// Validate checks if the manifests can be processed by this extractor
	Validate(manifests []*renderer.Manifest) error
	// SetOptions configures the extractor with the given options
	SetOptions(opts *Options)
	// GetOptions returns the current options
	GetOptions() *Options
}
