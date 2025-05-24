package ingestor

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FolderResolver implements SourceResolver for directories containing YAML files
type FolderResolver struct {
	source string
	opts   *Options
}

// NewFolderResolver creates a new FolderResolver
func NewFolderResolver(source string, opts *Options) *FolderResolver {
	return &FolderResolver{
		source: source,
		opts:   opts,
	}
}

// CanResolve checks if this resolver can handle the given source
func (r *FolderResolver) CanResolve(source string) bool {
	info, err := os.Stat(source)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// yamlFile represents a YAML file found in the directory
type yamlFile struct {
	path     string
	info     fs.FileInfo
	err      error
	contents []byte
}

// Resolve processes the source directory and returns a concatenated reader of all YAML files
func (r *FolderResolver) Resolve(ctx context.Context) (io.ReadCloser, *ResolverMetadata, error) {
	// Check if directory exists
	info, err := os.Stat(r.source)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("not a directory: %s", r.source)
	}

	// Create channels for parallel processing
	filesChan := make(chan yamlFile)
	errorsChan := make(chan error, 1)

	// Start file finder goroutine
	go func() {
		defer close(filesChan)

		// Create a map to track visited symlinks to prevent cycles
		visitedSymlinks := make(map[string]bool)

		// Create the base walk function
		baseWalkFunc := buildWalkFunc(ctx, filesChan, errorsChan)

		// Create a recursive walk function that handles symlinks
		var walkWithSymlinks func(string, fs.DirEntry, error) error
		walkWithSymlinks = func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Handle symlinks if enabled
			if r.opts != nil && r.opts.FollowSymlinks && d.Type()&os.ModeSymlink != 0 {
				// Get the absolute path of the symlink
				absPath, err := filepath.Abs(path)
				if err != nil {
					return fmt.Errorf("failed to get absolute path for %s: %w", path, err)
				}

				// Check if we've already visited this symlink
				if visitedSymlinks[absPath] {
					return nil
				}
				visitedSymlinks[absPath] = true

				// Evaluate the symlink
				target, err := filepath.EvalSymlinks(path)
				if err != nil {
					return fmt.Errorf("failed to evaluate symlink %s: %w", path, err)
				}

				// Get info about the target
				targetInfo, err := os.Stat(target)
				if err != nil {
					return fmt.Errorf("failed to stat symlink target %s: %w", target, err)
				}

				// Handle directory symlinks
				if targetInfo.IsDir() {
					return filepath.WalkDir(target, walkWithSymlinks)
				}

				// Handle file symlinks
				return baseWalkFunc(target, d, nil)
			}

			// For non-symlinks, use the base walk function
			return baseWalkFunc(path, d, err)
		}

		// Walk the directory with symlink support
		err := filepath.WalkDir(r.source, walkWithSymlinks)
		if err != nil {
			select {
			case errorsChan <- fmt.Errorf("failed to walk directory: %w", err):
			default:
			}
		}
	}()

	// Process found files
	var files []yamlFile
	var totalSize int64
	for file := range filesChan {
		if file.err != nil {
			return nil, nil, fmt.Errorf("error processing %s: %w", file.path, file.err)
		}
		files = append(files, file)
		totalSize += file.info.Size()
	}

	// Check for walk errors
	select {
	case err := <-errorsChan:
		return nil, nil, err
	default:
	}

	// No files found
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no YAML files found in directory")
	}

	// Create concatenated content with document separators
	var builder strings.Builder
	for i, file := range files {
		if i > 0 {
			builder.WriteString("\n---\n")
		}
		builder.Write(file.contents)
	}

	// Create metadata
	metadata := &ResolverMetadata{
		Type:    SourceTypeFolder,
		Path:    r.source,
		Size:    totalSize,
		ModTime: info.ModTime().Unix(),
	}

	return io.NopCloser(strings.NewReader(builder.String())), metadata, nil
}

// buildWalkFunc creates a WalkDirFunc that finds YAML files and validates them
func buildWalkFunc(ctx context.Context, filesChan chan<- yamlFile, errorsChan chan<- error) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			return err
		}

		// Read file contents
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Validate YAML if enabled
		if len(contents) > 0 && isValidYAML(string(contents)) {
			filesChan <- yamlFile{
				path:     path,
				info:     info,
				contents: contents,
			}
		}

		return nil
	}
}
