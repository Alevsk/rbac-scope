package extractor

import (
	"bytes"
	"context"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

func TestIdentityExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     int
		wantErr  bool
	}{
		{
			name: "valid service account",
			manifest: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-sa
  namespace: default
  labels:
    app: test
  annotations:
    description: "Test service account"
automountServiceAccountToken: true
secrets:
- name: test-secret
imagePullSecrets:
- name: docker-registry`,
			want:    1,
			wantErr: false,
		},
		{
			name: "multiple service accounts",
			manifest: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa1
  namespace: ns1
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa2
  namespace: ns2`,
			want:    2,
			wantErr: false,
		},
		{
			name: "non-service account resource",
			manifest: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  namespace: default`,
			want:    0,
			wantErr: false,
		},
		{
			name:     "empty input",
			manifest: "",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "invalid yaml",
			manifest: "invalid: [yaml",
			want:     0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewIdentityExtractor(nil)
			// Split manifest into multiple documents if needed
			docs := bytes.Split([]byte(tt.manifest), []byte("\n---\n"))
			var manifests []*renderer.Manifest
			for _, doc := range docs {
				manifests = append(manifests, &renderer.Manifest{Raw: doc})
			}
			result, err := e.Extract(context.Background(), manifests)

			if (err != nil) != tt.wantErr {
				t.Errorf("IdentityExtractor.Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			identities, ok := result.Raw.([]Identity)
			if !ok {
				t.Errorf("IdentityExtractor.Extract() result.Raw is not []Identity")
				return
			}

			if count := len(identities); count != tt.want {
				t.Errorf("IdentityExtractor.Extract() got %d identities, want %d", count, tt.want)
			}

			// Verify metadata
			if count, ok := result.Metadata["count"].(int); !ok || count != tt.want {
				t.Errorf("IdentityExtractor.Extract() metadata count = %v, want %d", count, tt.want)
			}
		})
	}
}
