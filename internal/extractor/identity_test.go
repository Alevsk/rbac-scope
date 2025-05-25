package extractor

import (
	"context"
	"testing"
)

func TestIdentityExtractor_Extract(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name: "valid service account",
			input: `apiVersion: v1
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
			input: `apiVersion: v1
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
			input: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  namespace: default`,
			want:    0,
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid yaml",
			input:   "invalid: [yaml",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewIdentityExtractor(nil)
			result, err := e.Extract(context.Background(), []byte(tt.input))

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
