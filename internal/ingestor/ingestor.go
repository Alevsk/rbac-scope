// Package ingestor provides functionality for ingesting RBAC policies from various sources
package ingestor

import (
	"context"
	"fmt"
	"time"

	"github.com/alevsk/rbac-ops/internal/extractor"
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
	Version   string `json:"version"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Success   bool   `json:"success"`
	Error     error  `json:"error"`
	Timestamp int64  `json:"timestamp"`
	// Extracted data from each extractor
	IdentityData *extractor.Result `json:"identity_data"`
	WorkloadData *extractor.Result `json:"workload_data"`
	RBACData     *extractor.Result `json:"rbac_data"`
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
	r, err := resolver.ResolverFactory(source, opts)
	if err != nil {
		return nil, err
	}

	// Create extractors
	ef := extractor.NewExtractorFactory()

	identityExtractor, err := ef.NewExtractor("identity", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity extractor: %w", err)
	}

	workloadExtractor, err := ef.NewExtractor("workload", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create workload extractor: %w", err)
	}

	rbacExtractor, err := ef.NewExtractor("rbac", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC extractor: %w", err)
	}

	// Resolve the source
	renderedResult, metadata, err := r.Resolve(ctx)
	if err != nil {
		return nil, err
	}

	// Extract data using each extractor
	identityData, err := identityExtractor.Extract(ctx, renderedResult.Manifests)
	if err != nil {
		return nil, fmt.Errorf("identity extraction failed: %w", err)
	}

	workloadData, err := workloadExtractor.Extract(ctx, renderedResult.Manifests)
	if err != nil {
		return nil, fmt.Errorf("workload extraction failed: %w", err)
	}

	rbacData, err := rbacExtractor.Extract(ctx, renderedResult.Manifests)
	if err != nil {
		return nil, fmt.Errorf("RBAC extraction failed: %w", err)
	}

	return &Result{
		Name:         metadata.Name,
		Version:      metadata.Version,
		Source:       metadata.Path,
		Success:      true,
		Timestamp:    time.Now().Unix(),
		IdentityData: identityData,
		WorkloadData: workloadData,
		RBACData:     rbacData,
	}, nil
}
