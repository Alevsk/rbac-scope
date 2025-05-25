// Package extractor provides functionality to extract and analyze Kubernetes RBAC information
package extractor

import (
	"context"
	"fmt"
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
		StrictParsing:   true,
		IncludeMetadata: true,
	}
}

// Result represents the structured output from an extractor
type Result struct {
	// Raw contains the raw extracted data
	Raw interface{}
	// Metadata contains additional information about the extraction
	Metadata map[string]interface{}
}

// NewResult creates a new Result with initialized fields
func NewResult() *Result {
	return &Result{
		Metadata: make(map[string]interface{}),
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
	// Extract processes the input and returns structured data
	Extract(ctx context.Context, input []byte) (*Result, error)
	// Validate checks if the input can be processed by this extractor
	Validate(input []byte) error
	// SetOptions configures the extractor with the given options
	SetOptions(opts *Options)
	// GetOptions returns the current options
	GetOptions() *Options
}
