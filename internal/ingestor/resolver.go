package ingestor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// String returns the string representation of a SourceType
func (st SourceType) String() string {
	switch st {
	case SourceTypeFile:
		return "file"
	case SourceTypeRemote:
		return "remote"
	case SourceTypeFolder:
		return "folder"
	default:
		return "unknown"
	}
}

// SourceResolver defines the interface that all source resolvers must implement
type SourceResolver interface {
	// CanResolve checks if this resolver can handle the given source
	CanResolve(source string) bool

	// Resolve processes the source and returns a reader for its contents
	// For directories, this should return an error as they need special handling
	Resolve(ctx context.Context) (io.ReadCloser, *ResolverMetadata, error)
}

// ResolverFactory creates the appropriate resolver for a given source
func ResolverFactory(source string, opts *Options) (SourceResolver, error) {
	if source == "" {
		return nil, fmt.Errorf("empty source")
	}

	// Try to parse as URL first
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		ext := strings.ToLower(filepath.Ext(source))
		if ext != ".yaml" && ext != ".yml" {
			return nil, fmt.Errorf("URL does not point to a YAML file: %s", source)
		}
		return NewRemoteYAMLResolver(source, opts, defaultHTTPClient)
	}

	// Check if it's a directory
	info, err := os.Stat(source)
	if err == nil && info.IsDir() {
		resolver := NewFolderResolver(source, opts)
		if resolver.CanResolve(source) {
			return resolver, nil
		}
		return nil, fmt.Errorf("directory cannot be resolved")
	}

	// Try local YAML resolver
	resolver := NewLocalYAMLResolver(source, opts)
	if resolver.CanResolve(source) {
		return resolver, nil
	}

	return nil, fmt.Errorf("no suitable resolver found for source: %s", source)
}
