package resolver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			opts := &Options{ValidateYAML: tt.validate}
			r, err := NewRemoteYAMLResolver(server.URL+"/test.yaml", opts, defaultHTTPClient)
			if err != nil {
				t.Fatalf("NewRemoteYAMLResolver() error = %v", err)
			}

			ctx := context.Background()
			if tt.name == "context cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			reader, metadata, err := r.Resolve(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteYAMLResolver.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errType != nil && !strings.Contains(err.Error(), tt.errType.Error()) {
					t.Errorf("RemoteYAMLResolver.Resolve() error = %v, want %v", err, tt.errType)
				}
				return
			}

			defer reader.Close()

			if metadata == nil {
				t.Error("RemoteYAMLResolver.Resolve() metadata is nil")
				return
			}

			if metadata.Type != SourceTypeRemote {
				t.Errorf("RemoteYAMLResolver.Resolve() type = %v, want %v", metadata.Type, SourceTypeRemote)
			}

			content, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("Failed to read content: %v", err)
				return
			}

			if !strings.Contains(string(content), "apiVersion") {
				t.Error("Content does not contain expected YAML")
			}
		})
	}
}
