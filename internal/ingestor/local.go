package ingestor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LocalYAMLResolver implements SourceResolver for local YAML files
type LocalYAMLResolver struct {
	source string
	opts   *Options
}

// NewLocalYAMLResolver creates a new LocalYAMLResolver
func NewLocalYAMLResolver(source string, opts *Options) *LocalYAMLResolver {
	return &LocalYAMLResolver{
		source: source,
		opts:   opts,
	}
}

// CanResolve checks if this resolver can handle the given source
func (r *LocalYAMLResolver) CanResolve(source string) bool {
	// Check if file exists and has a YAML extension
	if _, err := os.Stat(source); err != nil {
		return false
	}

	ext := strings.ToLower(filepath.Ext(source))
	return ext == ".yaml" || ext == ".yml"
}

// Resolve processes the source and returns a reader for its contents
func (r *LocalYAMLResolver) Resolve(ctx context.Context) (io.ReadCloser, *ResolverMetadata, error) {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	// Verify file exists and get info
	info, err := os.Stat(r.source)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Ensure it's a regular file
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("not a regular file: %s", r.source)
	}

	// Open the file
	file, err := os.Open(r.source)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}

	// If YAML validation is enabled, verify the content
	if r.opts != nil && r.opts.ValidateYAML {
		// Read the entire file for validation
		content, err := io.ReadAll(file)
		if err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		// Basic YAML validation (presence of required characters)
		if !isValidYAML(string(content)) {
			file.Close()
			return nil, nil, ErrInvalidYAML
		}

		// Seek back to start for the caller
		if _, err := file.Seek(0, 0); err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("failed to seek file: %w", err)
		}
	}

	// Create metadata
	metadata := &ResolverMetadata{
		Type:    SourceTypeFile,
		Path:    r.source,
		Size:    info.Size(),
		ModTime: info.ModTime().Unix(),
	}

	return file, metadata, nil
}

// isValidYAML performs basic YAML validation
// This is a simple check for common YAML markers
func isValidYAML(content string) bool {
	// Remove whitespace
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return false
	}

	// Check for common YAML markers
	hasMarker := strings.Contains(trimmed, ":") || // key-value pairs
		strings.Contains(trimmed, "- ") || // array items
		strings.Contains(trimmed, "---") // document separator

	return hasMarker
}
