package extractor

import (
	"bytes"
	"context"
	"errors"
	"reflect"
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

			identityData, ok := result.Data["identities"].(map[string]map[string]Identity)
			if !ok {
				t.Errorf("IdentityExtractor.Extract() result.Data[\"identities\"] is not map[string]map[string]Identity")
				return
			}

			// Count total identities across all namespaces
			totalIdentities := 0
			for _, namespaceMap := range identityData {
				totalIdentities += len(namespaceMap)
			}

			if totalIdentities != tt.want {
				t.Errorf("IdentityExtractor.Extract() got %d identities, want %d", totalIdentities, tt.want)
			}

			// Verify metadata
			if count, ok := result.Metadata["count"].(int); !ok || count != tt.want {
				t.Errorf("IdentityExtractor.Extract() metadata count = %v, want %d", count, tt.want)
			}
		})
	}
}

func TestIdentityExtractor_Validate(t *testing.T) {
	e := NewIdentityExtractor(nil)

	if err := e.Validate(nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("Validate(nil) error = %v, want %v", err, ErrInvalidInput)
	}

	err := e.Validate([]*renderer.Manifest{{}})
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Errorf("Validate(empty manifest) error = %v, want %v", err, ErrInvalidInput)
	}

	if err := e.Validate([]*renderer.Manifest{{Raw: []byte("a: b")}}); err != nil {
		t.Errorf("Validate(valid) unexpected error: %v", err)
	}
}

func TestIdentityExtractor_SetGetOptions(t *testing.T) {
	e := NewIdentityExtractor(nil)
	def := e.GetOptions()
	custom := &Options{StrictParsing: false, IncludeMetadata: false}
	e.SetOptions(custom)
	if e.GetOptions() != custom {
		t.Errorf("GetOptions() did not return set options")
	}

	e.SetOptions(nil)
	if e.GetOptions() != custom {
		t.Errorf("SetOptions(nil) should not modify options")
	}

	if reflect.DeepEqual(def, custom) {
		t.Errorf("default and custom options unexpectedly equal")
	}
}

func TestIdentityExtractor_Extract_NonStrict(t *testing.T) {
	e := NewIdentityExtractor(nil)
	opts := e.GetOptions()
	opts.StrictParsing = false
	e.SetOptions(opts)
	manifests := []*renderer.Manifest{{Raw: []byte("invalid: [yaml")}}
	result, err := e.Extract(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}
	if count, ok := result.Metadata["count"].(int); !ok || count != 0 {
		t.Errorf("metadata count = %v, want 0", result.Metadata["count"])
	}
}
