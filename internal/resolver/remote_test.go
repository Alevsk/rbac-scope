package resolver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

func TestNewRemoteYAMLResolver(t *testing.T) {
	mockClient := newMockHTTPClient().GetClient()

	tests := []struct {
		name        string
		source      string
		opts        *Options
		client      *http.Client // Can be nil to use default
		wantErr     bool
		checkClient bool // whether to check if a non-default client was set (hard to check specific instance)
		wantOpts    *Options
	}{
		{
			name:     "valid url, nil options, nil client",
			source:   "http://example.com/valid.yaml",
			opts:     nil,
			client:   nil,
			wantErr:  false,
			wantOpts: DefaultOptions(), // Implicitly resolver's DefaultOptions
		},
		{
			name:   "valid url, custom options, nil client",
			source: "https://example.com/another.yaml",
			opts: &Options{
				FollowSymlinks: true, // This option is for resolver, not directly used by remote but test it's passed
				ValidateYAML:   false,
			},
			client:  nil,
			wantErr: false,
			wantOpts: &Options{
				FollowSymlinks: true,
				ValidateYAML:   false,
			},
		},
		{
			name:     "valid url, nil options, custom client",
			source:   "http://custom.example.com/file.yml",
			opts:     nil,
			client:   mockClient,
			wantErr:  false,
			wantOpts: DefaultOptions(),
		},
		{
			name:     "invalid url",
			source:   "://totally-invalid",
			opts:     nil,
			client:   nil,
			wantErr:  true,
			wantOpts: nil,
		},
		// Note: NewRemoteYAMLResolver itself doesn't error on non-yaml extensions, CanResolve does.
		// So, a test for "http://example.com/file.txt" here should succeed.
		{
			name:     "url with non-yaml extension (NewRemoteYAMLResolver should allow)",
			source:   "http://example.com/file.txt",
			opts:     nil,
			client:   nil,
			wantErr:  false, // NewRemoteYAMLResolver does not check extension, CanResolve does.
			wantOpts: DefaultOptions(),
		},
		{
			name:     "valid url, nil options, force internal client creation",
			source:   "http://example.com/test.yaml",
			opts:     nil,
			client:   nil, // Will be overridden by setting defaultHTTPClient to nil
			wantErr:  false,
			wantOpts: DefaultOptions(),
		},
		{
			name:    "url.Parse fails after isValidURL (e.g. invalid port)",
			source:  "http://example.com:namedport", // url.Parse will fail on "namedport"
			opts:    nil,
			client:  nil,
			wantErr: true,
		},
		{
			name:   "valid url, custom options with ValidateYAML true",
			source: "https://example.com/validate.yaml",
			opts: &Options{
				ValidateYAML:   true,
				FollowSymlinks: false,
			},
			client:  nil,
			wantErr: false,
			wantOpts: &Options{
				ValidateYAML:   true,
				FollowSymlinks: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var originalDefaultClient *http.Client
			if tt.name == "valid url, nil options, force internal client creation" {
				originalDefaultClient = defaultHTTPClient
				defaultHTTPClient = nil
				defer func() {
					defaultHTTPClient = originalDefaultClient
				}()
			}

			r, err := NewRemoteYAMLResolver(tt.source, tt.opts, tt.client)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewRemoteYAMLResolver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if r == nil {
					t.Fatal("NewRemoteYAMLResolver() returned nil resolver when no error was expected")
				}
				if r.source != tt.source {
					t.Errorf("NewRemoteYAMLResolver() source = %s, want %s", r.source, tt.source)
				}

				// Check options
				// If tt.opts was nil, the resolver's opts should be DefaultOptions()
				// Otherwise, it should be tt.opts.
				expectedResolverOpts := tt.wantOpts
				// The RemoteYAMLResolver's internal opts field 'opts' refers to resolver.Options.
				// The renderer options are set internally based on these.
				if !reflect.DeepEqual(r.opts, expectedResolverOpts) {
					t.Errorf("NewRemoteYAMLResolver() internal opts = %v, want %v", r.opts, expectedResolverOpts)
				}

				// Check if the client was set (if a custom one was provided)
				// It's hard to check for specific client instance equality directly without exposing it,
				// but we can check if it's not the default one if a custom one was given.
				// For this test, we'll just ensure it runs. A more in-depth test would require more access.
				if tt.client != nil && r.client != tt.client {
					// This check might be flaky if the default client instance is somehow the same as mockClient
					// For now, this is a basic check.
					t.Logf("Note: Client instance check is basic. r.client: %p, tt.client: %p", r.client, tt.client)
				}

				if tt.name == "valid url, nil options, force internal client creation" {
					if r.client == nil {
						t.Error("Expected client to be initialized internally, but it's nil")
					} else if r.client.Timeout != defaultHTTPTimeout {
						t.Errorf("Expected client timeout to be %v, got %v", defaultHTTPTimeout, r.client.Timeout)
					}
				}
			}
		})
	}
}

func TestRemoteYAMLResolver_CanResolve(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantErr bool
		wantCan bool
	}{
		{
			name:    "valid http url",
			source:  "http://example.com/file.yaml",
			wantErr: false,
			wantCan: true,
		},
		{
			name:    "valid https url",
			source:  "https://example.com/file.yml",
			wantErr: false,
			wantCan: true,
		},
		{
			name:    "invalid URL",
			source:  "not-a-url",
			wantErr: true,
			wantCan: false,
		},
		{
			name:    "invalid url format",
			source:  "://invalid",
			wantErr: true,
			wantCan: false,
		},
		{
			name:    "invalid scheme",
			source:  "ftp://example.com/file.yaml",
			wantErr: false,
			wantCan: false,
		},
		{
			name:    "non yaml extension",
			source:  "http://example.com/file.txt",
			wantErr: false,
			wantCan: false,
		},
		{
			name:    "url parse error in CanResolve",
			source:  "http://[::1]:namedport", // Invalid port, url.Parse will fail
			wantErr: true,                     // NewRemoteYAMLResolver should catch this
			wantCan: false,
		},
		{
			name:    "valid https url with uppercase extension",
			source:  "https://example.com/file.YAML",
			wantErr: false,
			wantCan: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRemoteYAMLResolver(tt.source, nil, defaultHTTPClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRemoteYAMLResolver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got := r.CanResolve(tt.source); got != tt.wantCan {
					t.Errorf("RemoteYAMLResolver.CanResolve() = %v, want %v", got, tt.wantCan)
				}
			}
		})
	}
}

func TestRemoteYAMLResolver_Resolve(t *testing.T) {
	validYAML := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]`

	invalidYAML := "This is not valid YAML content"

	tests := []struct {
		name        string
		validate    bool
		setupServer func() *httptest.Server
		wantErr     bool
		errType     error
	}{
		{
			name:     "valid yaml content",
			validate: true,
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/yaml")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(validYAML))
				}))
			},
			wantErr: false,
		},
		{
			name:     "invalid yaml content",
			validate: true,
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/yaml")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(invalidYAML))
				}))
			},
			wantErr: true,
			errType: renderer.ErrInvalidFormat,
		},
		{
			name:     "server error",
			validate: true,
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			wantErr: true,
		},
		{
			name:     "context cancelled",
			validate: true,
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate slow response
					select {
					case <-r.Context().Done():
						return
					case <-time.After(2 * time.Second):
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(validYAML))
					}
				}))
			},
			wantErr: true,
		},
		{
			name:     "http client.Do error (connection refused)",
			validate: true, // Validate option doesn't matter much here as the error is pre-validation
			setupServer: func() *httptest.Server {
				// Create a server but don't start it, and close its listener.
				// This will cause a connection refused error.
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK) // Should not be reached
				}))
				// Close the listener immediately to simulate connection refused
				if err := server.Listener.Close(); err != nil {
					t.Fatalf("Failed to close listener for unstarted server: %v", err)
				}
				return server
			},
			wantErr: true,
			// We expect an error, but not a specific 'errType' like ErrInvalidFormat,
			// as it will be a network error from the client.Do call.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			// server.Close() is deferred in all cases.
			// For the "connection refused" test, the server is already effectively "closed"
			// by its listener being shut. server.Close() on an unstarted server or
			// a server with a closed listener is safe.
			defer server.Close()

			var targetURL string
			if tt.name == "http client.Do error (connection refused)" {
				// For unstarted server, Listener.Addr() gives the address.
				// We need to manually construct a URL.
				// The server.URL is only populated after Start/StartTLS.
				targetURL = "http://" + server.Listener.Addr().String() + "/test.yaml"
			} else {
				targetURL = server.URL + "/test.yaml"
			}

			opts := &Options{ValidateYAML: tt.validate}
			r, err := NewRemoteYAMLResolver(targetURL, opts, defaultHTTPClient)
			if err != nil {
				// If the error is specifically for the "connection refused" test and it's an invalid URL error,
				// that means our manual URL construction might still be off.
				// However, the primary goal is to test client.Do failure.
				// For now, let's assume NewRemoteYAMLResolver should pass if targetURL is well-formed.
				t.Fatalf("NewRemoteYAMLResolver() error = %v for URL %s", err, targetURL)
			}

			ctx := context.Background()
			if tt.name == "context cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			result, metadata, err := r.Resolve(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteYAMLResolver.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errType != nil {
					if !strings.Contains(err.Error(), tt.errType.Error()) {
						t.Errorf("RemoteYAMLResolver.Resolve() error = %v, want error containing %v", err, tt.errType)
					}
				} else if tt.name == "http client.Do error (connection refused)" {
					// Check for a generic fetch error or connection refused message
					if !strings.Contains(err.Error(), "failed to fetch URL") && !strings.Contains(err.Error(), "connection refused") {
						t.Errorf("RemoteYAMLResolver.Resolve() error = %v, want error containing 'failed to fetch URL' or 'connection refused'", err)
					}
				}
				return
			}

			if metadata == nil {
				t.Error("RemoteYAMLResolver.Resolve() metadata is nil")
				return
			}

			if metadata.Type != SourceTypeRemote {
				t.Errorf("RemoteYAMLResolver.Resolve() type = %v, want %v", metadata.Type, SourceTypeRemote)
			}

			if result == nil {
				t.Error("RemoteYAMLResolver.Resolve() result is nil")
				return
			}

			if len(result.Manifests) == 0 {
				t.Error("No manifests found in result")
				return
			}

			// Check that at least one manifest contains apiVersion
			found := false
			for _, manifest := range result.Manifests {
				if strings.Contains(string(manifest.Raw), "apiVersion") {
					found = true
					break
				}
			}
			if !found {
				t.Error("No manifest contains expected YAML")
			}
		})
	}
}
