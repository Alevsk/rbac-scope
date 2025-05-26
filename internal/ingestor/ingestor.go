// Package ingestor provides functionality for ingesting RBAC policies from various sources
package ingestor

import (
	"context"
	"fmt"
	"time"

	"github.com/alevsk/rbac-ops/internal/resolver"
)

// Options holds configuration for the ingestor
type Options struct {
	// MaxConcurrency defines the maximum number of concurrent ingestion operations
	MaxConcurrency int
	// FollowSymlinks determines if symlinks should be followed during directory traversal
	FollowSymlinks bool
	// ValidateYAML enables strict YAML validation during ingestion
	ValidateYAML bool
}

// DefaultOptions returns the default ingestor options
func DefaultOptions() *Options {
	return &Options{
		MaxConcurrency: 4,
		FollowSymlinks: false,
		ValidateYAML:   true,
	}
}

// Ingestor manages the ingestion of RBAC policies
type Ingestor struct {
	opts *Options
}

// New creates a new Ingestor with the given options
func New(opts *Options) *Ingestor {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Ingestor{
		opts: opts,
	}
}

// Error types for ingestion operations
var (
	ErrInvalidSource = fmt.Errorf("invalid source")
	ErrInvalidYAML   = fmt.Errorf("invalid YAML content")
)

// Result represents the outcome of an ingestion operation
type Result struct {
	Source    string
	Success   bool
	Error     error
	Timestamp int64
}

// Ingest starts the ingestion process from the given source
// The context can be used to cancel the operation
func (i *Ingestor) Ingest(ctx context.Context, source string) (*Result, error) {
	if source == "" {
		return nil, ErrInvalidSource
	}

	opts := &resolver.Options{
		ValidateYAML:   i.opts.ValidateYAML,
		FollowSymlinks: i.opts.FollowSymlinks,
	}
	// Get the appropriate resolver for this source
	resolver, err := resolver.ResolverFactory(source, opts)
	if err != nil {
		return nil, err
	}

	// Resolve the source
	reader, metadata, err := resolver.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// TODO: Process the resolved content (will be implemented in subsequent tasks)

	return &Result{
		Source:    metadata.Path,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}, nil
}
