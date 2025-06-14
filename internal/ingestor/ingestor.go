// Package ingestor provides functionality for ingesting RBAC policies from various sources
package ingestor

import (
	"context"
	"fmt"
	"time"

	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/formatter"
	"github.com/alevsk/rbac-ops/internal/resolver"
	"github.com/alevsk/rbac-ops/internal/types"
)

// Options holds configuration for the ingestor
type Options struct {
	// MaxConcurrency defines the maximum number of concurrent ingestion operations
	MaxConcurrency int
	// FollowSymlinks determines if symlinks should be followed during directory traversal
	FollowSymlinks bool
	// ValidateYAML enables strict YAML validation during ingestion
	ValidateYAML bool
	// OutputFormat defines the format of the output
	OutputFormat string
	// IncludeMetadata determines if metadata should be included in the output
	IncludeMetadata bool
	// Values is a file path to a values.yaml file used for rendering a helm chart
	Values string
}

// DefaultOptions returns the default ingestor options
func DefaultOptions() *Options {
	return &Options{
		MaxConcurrency:  4,
		FollowSymlinks:  false,
		ValidateYAML:    true,
		OutputFormat:    "table",
		IncludeMetadata: true,
		Values:          "",
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

// Result is an alias for types.Result
type Result = types.Result

// Ingest starts the ingestion process from the given source
// The context can be used to cancel the operation
func (i *Ingestor) Ingest(ctx context.Context, source string) (*Result, error) {
	if source == "" {
		return nil, ErrInvalidSource
	}

	opts := &resolver.Options{
		ValidateYAML:   i.opts.ValidateYAML,
		FollowSymlinks: i.opts.FollowSymlinks,
		Values:         i.opts.Values,
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

	// Convert extractor results to ExtractedData
	identityExtracted := &types.ExtractedData{
		Data:     identityData.Data,
		Metadata: identityData.Metadata,
	}
	workloadExtracted := &types.ExtractedData{
		Data:     workloadData.Data,
		Metadata: workloadData.Metadata,
	}
	rbacExtracted := &types.ExtractedData{
		Data:     rbacData.Data,
		Metadata: rbacData.Metadata,
	}

	// Create result
	result := types.Result{
		Version:      metadata.Version,
		Name:         metadata.Name,
		Source:       metadata.Path,
		Success:      true,
		Timestamp:    time.Now().Unix(),
		IdentityData: identityExtracted,
		WorkloadData: workloadExtracted,
		RBACData:     rbacExtracted,
		Extra:        metadata.Extra,
	}

	fOpts := &formatter.Options{
		IncludeMetadata: i.opts.IncludeMetadata,
	}

	// Format the result using the specified output format
	formatType, err := formatter.ParseType(i.opts.OutputFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse formatter type: %w", err)
	}

	f, err := formatter.NewFormatter(formatType, fOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create formatter: %w", err)
	}

	formatted, err := f.Format(result)
	if err != nil {
		return nil, fmt.Errorf("failed to format result: %w", err)
	}

	result.OutputFormatted = formatted
	return &result, nil
}
