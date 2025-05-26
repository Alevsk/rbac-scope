package resolver

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alevsk/rbac-ops/internal/renderer"
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

// Resolve processes the source directory and returns the rendered manifests
func (r *FolderResolver) Resolve(ctx context.Context) (*renderer.Result, *ResolverMetadata, error) {
	// Check if directory exists
	info, err := os.Stat(r.source)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("not a directory: %s", r.source)
	}

	// Detect the renderer type
	rendererType, err := DetectRendererType(r.source)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect renderer type: %w", err)
	}

	// Get the appropriate renderer and metadata
	renderer, err := GetRendererForType(rendererType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get renderer: %w", err)
	}

	// Create resolver metadata
	meta := &ResolverMetadata{
		Type:         SourceTypeFolder,
		RendererType: rendererType,
		Path:         r.source,
		Size:         0, // Will be updated after reading files
		ModTime:      time.Now(),
		Extra:        make(map[string]interface{}),
	}

	// If it's a Helm chart or Kustomize directory, read all files and pass them to the appropriate renderer
	if rendererType == RendererTypeHelm || rendererType == RendererTypeKustomize {
		// Read the entire directory
		files := make(map[string][]byte)
		err := filepath.Walk(r.source, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				content, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read file %s: %w", path, err)
				}
				relPath, err := filepath.Rel(r.source, path)
				if err != nil {
					return fmt.Errorf("failed to get relative path for %s: %w", path, err)
				}
				files[relPath] = content
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to walk directory: %w", err)
		}

		// Get the main file content based on renderer type
		var mainFile string
		if rendererType == RendererTypeHelm {
			mainFile = "Chart.yaml"
		} else {
			mainFile = "kustomization.yaml"
		}

		// Add all files to the renderer
		for name, content := range files {
			if err := renderer.AddFile(name, content); err != nil {
				return nil, nil, fmt.Errorf("failed to add file %s: %w", name, err)
			}
		}

		// Render using the appropriate renderer
		result, err := renderer.Render(ctx, files[mainFile])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to render: %w", err)
		}

		return result, meta, nil
	}

	// For YAML files, use the existing logic
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

	// Combine all YAML files into a single document
	var builder strings.Builder
	for i, file := range files {
		if i > 0 {
			builder.WriteString("\n---\n")
		}
		builder.Write(file.contents)
	}

	// Use renderer to validate and process the content
	yamlRenderer, err := GetRendererForType(RendererTypeYAML)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get renderer: %w", err)
	}

	content := []byte(builder.String())
	if err := yamlRenderer.Validate(content); err != nil {
		return nil, nil, err
	}

	// Render the content to ensure it's valid RBAC
	result, err := yamlRenderer.Render(ctx, content)
	if err != nil {
		return nil, nil, err
	}

	// Create metadata
	metadata := &ResolverMetadata{
		Type:    SourceTypeFolder,
		Path:    r.source,
		Size:    totalSize,
		ModTime: time.Now(),
		Extra: map[string]interface{}{
			"manifests": len(result.Manifests),
			"warnings":  result.Warnings,
		},
	}

	return result, metadata, nil
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
