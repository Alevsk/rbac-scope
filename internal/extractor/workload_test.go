package extractor

import (
	"bytes"
	"context"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
	"gopkg.in/yaml.v3"
)

func TestWorkloadExtractor_Extract(t *testing.T) {
	tests := []struct {
		name          string
		manifest      string
		want          int
		wantErr       bool
		strictParsing bool
	}{
		{
			name: "valid pod",
			manifest: `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  labels:
    app: test
spec:
  serviceAccountName: test-sa
  securityContext:
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:1.14.2
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"`,
			want:    1,
			wantErr: false,
		},
		{
			name: "valid deployment",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      serviceAccountName: test-sa
      securityContext:
        runAsNonRoot: true
      containers:
      - name: nginx
        image: nginx:1.14.2`,
			want:    1,
			wantErr: false,
		},
		{
			name: "multiple workloads",
			manifest: `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  serviceAccountName: test-sa
  containers:
  - name: nginx
    image: nginx:1.14.2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  namespace: default
spec:
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      serviceAccountName: test-sa
      containers:
      - name: nginx
        image: nginx:1.14.2`,
			want:    2,
			wantErr: false,
		},
		{
			name: "non-workload resource",
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
			// Set strict parsing if specified
			opts := DefaultOptions()
			opts.StrictParsing = tt.strictParsing
			e := NewWorkloadExtractor(opts)

			// Split manifest into multiple documents if needed
			docs := bytes.Split([]byte(tt.manifest), []byte("\n---\n"))
			var manifests []*renderer.Manifest
			for _, doc := range docs {
				var content map[string]interface{}
				if err := yaml.Unmarshal(doc, &content); err == nil {
					manifests = append(manifests, &renderer.Manifest{Raw: doc, Content: content})
				}
			}
			result, err := e.Extract(context.Background(), manifests)

			if (err != nil) != tt.wantErr {
				t.Errorf("WorkloadExtractor.Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			workloadData, ok := result.Data["workloads"].(map[string]map[string][]Workload)
			if !ok {
				t.Errorf("WorkloadExtractor.Extract() result.Data[\"workloads\"] is not map[string]map[string][]Workload")
				return
			}

			// Count total workloads across all service accounts and namespaces
			totalWorkloads := 0
			for _, saMap := range workloadData {
				for _, nsWorkloads := range saMap {
					totalWorkloads += len(nsWorkloads)
				}
			}

			if totalWorkloads != tt.want {
				t.Errorf("WorkloadExtractor.Extract() got %d workloads, want %d", totalWorkloads, tt.want)
			}

			// Verify metadata
			if count, ok := result.Metadata["count"].(int); !ok || count != tt.want {
				t.Errorf("WorkloadExtractor.Extract() metadata count = %v, want %d", count, tt.want)
			}
		})
	}
}
