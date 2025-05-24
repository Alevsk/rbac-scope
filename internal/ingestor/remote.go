package ingestor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// defaultHTTPClient is the default HTTP client used by RemoteYAMLResolver
// This can be overridden for testing
var defaultHTTPClient = http.DefaultClient

// Default timeout for HTTP requests
const defaultHTTPTimeout = 30 * time.Second

// RemoteYAMLResolver implements SourceResolver for remote HTTP/HTTPS resources
type RemoteYAMLResolver struct {
	source  string
	opts    *Options
	client  *http.Client
	baseURL *url.URL
}

// isValidURL checks if a string is a valid URL
func isValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// NewRemoteYAMLResolver creates a new RemoteYAMLResolver
func NewRemoteYAMLResolver(source string, opts *Options, client *http.Client) (*RemoteYAMLResolver, error) {
	if !isValidURL(source) {
		return nil, fmt.Errorf("invalid URL: %s", source)
	}

	baseURL, err := url.Parse(source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Use provided client or default client if not provided
	if client == nil {
		client = defaultHTTPClient
		if client == nil {
			client = &http.Client{
				Timeout: defaultHTTPTimeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 10 {
						return fmt.Errorf("too many redirects")
					}
					return nil
				},
			}
		}
	}

	return &RemoteYAMLResolver{
		source:  source,
		opts:    opts,
		client:  client,
		baseURL: baseURL,
	}, nil
}

// CanResolve checks if this resolver can handle the given source
func (r *RemoteYAMLResolver) CanResolve(source string) bool {
	u, err := url.Parse(source)
	if err != nil {
		return false
	}

	// Check if it's HTTP/HTTPS
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Check file extension if present
	ext := strings.ToLower(path.Ext(u.Path))
	return ext == ".yaml" || ext == ".yml"
}

// Resolve processes the source and returns a reader for its contents
func (r *RemoteYAMLResolver) Resolve(ctx context.Context) (io.ReadCloser, *ResolverMetadata, error) {
	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.source, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add appropriate headers
	req.Header.Set("Accept", "application/yaml,text/yaml,text/plain")
	req.Header.Set("User-Agent", "rbac-ops/1.0")

	// Perform the request
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch URL: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("HTTP request failed with status: %s", resp.Status)
	}

	// If YAML validation is enabled
	if r.opts != nil && r.opts.ValidateYAML {
		// Read the entire body for validation
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, nil, fmt.Errorf("failed to read response body: %w", err)
		}

		// Basic YAML validation
		if !isValidYAML(string(content)) {
			resp.Body.Close()
			return nil, nil, ErrInvalidYAML
		}

		// Create a new reader from the content
		return io.NopCloser(strings.NewReader(string(content))), &ResolverMetadata{
			Type:    SourceTypeRemote,
			Path:    r.source,
			Size:    int64(len(content)),
			ModTime: time.Now().Unix(),
		}, nil
	}

	// Create metadata from response
	metadata := &ResolverMetadata{
		Type:    SourceTypeRemote,
		Path:    r.source,
		Size:    resp.ContentLength,
		ModTime: time.Now().Unix(),
	}

	return resp.Body, metadata, nil
}
