package extractor

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
	"gopkg.in/yaml.v3"
)

func TestWorkloadExtractor_GetSetOptions(t *testing.T) {
	defaultOpts := DefaultOptions()
	e := NewWorkloadExtractor(nil) // Starts with default options

	// 1. Test GetOptions returns default options initially
	if !reflect.DeepEqual(e.GetOptions(), defaultOpts) {
		t.Errorf("GetOptions() initial = %v, want %v", e.GetOptions(), defaultOpts)
	}

	// 2. Test SetOptions with new options
	newOpts := &Options{StrictParsing: true, IncludeMetadata: false}
	e.SetOptions(newOpts)
	if !reflect.DeepEqual(e.GetOptions(), newOpts) {
		t.Errorf("GetOptions() after SetOptions(newOpts) = %v, want %v", e.GetOptions(), newOpts)
	}

	// 3. Test SetOptions with nil (should retain current options, not reset to default)
	//    Based on typical SetOption behavior; if it's meant to reset, this test would change.
	//    The current implementation `if opts != nil { e.opts = opts }` means it retains.
	e.SetOptions(nil)
	if !reflect.DeepEqual(e.GetOptions(), newOpts) {
		t.Errorf("GetOptions() after SetOptions(nil) = %v, want %v (should be unchanged)", e.GetOptions(), newOpts)
	}

	// 4. Test setting back to default like options
	// Create a new default options instance to avoid pointer comparison issues
	anotherDefaultOpts := DefaultOptions()
	e.SetOptions(anotherDefaultOpts)
	if !reflect.DeepEqual(e.GetOptions(), anotherDefaultOpts) {
		t.Errorf("GetOptions() after SetOptions(anotherDefaultOpts) = %v, want %v", e.GetOptions(), anotherDefaultOpts)
	}
}

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
			name: "valid deployment without namespace",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
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
			name:     "invalid yaml",
			manifest: "invalid: [yaml",
			want:     0,
			wantErr:  true,
		},
		{
			name: "valid statefulset",
			manifest: `apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: test-statefulset
  namespace: test-ns
spec:
  serviceName: "test-svc"
  replicas: 1
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      serviceAccountName: test-sa-sts
      containers:
      - name: main-container
        image: main-image:v1`,
			want:    1,
			wantErr: false,
		},
		{
			name: "valid daemonset",
			manifest: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test-daemonset
  namespace: test-ds-ns
spec:
  selector:
    matchLabels:
      app: test-app-ds
  template:
    metadata:
      labels:
        app: test-app-ds
    spec:
      serviceAccountName: test-sa-ds
      containers:
      - name: ds-container
        image: ds-image:latest`,
			want:    1,
			wantErr: false,
		},
		{
			name: "valid job",
			manifest: `apiVersion: batch/v1
kind: Job
metadata:
  name: test-job
  namespace: test-job-ns
spec:
  template:
    spec:
      serviceAccountName: test-sa-job
      restartPolicy: Never
      containers:
      - name: job-container
        image: job-image:batch`,
			want:    1,
			wantErr: false,
		},
		{
			name: "valid cronjob",
			manifest: `apiVersion: batch/v1
kind: CronJob
metadata:
  name: test-cronjob
  namespace: test-cj-ns
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: test-sa-cj
          restartPolicy: OnFailure
          containers:
          - name: cj-container
            image: cj-image:stable`,
			want:    1,
			wantErr: false,
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
				// If no workloads are expected and the result is empty, this is fine.
				if tt.want == 0 && (result.Data["workloads"] == nil || len(workloadData) == 0) {
					// continue
				} else {
					t.Errorf("WorkloadExtractor.Extract() result.Data[\"workloads\"] is not map[string]map[string][]Workload, got: %T", result.Data["workloads"])
					return
				}
			}

			// Count total workloads across all service accounts and namespaces
			totalWorkloads := 0
			var extractedWorkloads []Workload
			for _, saMap := range workloadData {
				for _, nsWorkloads := range saMap {
					totalWorkloads += len(nsWorkloads)
					extractedWorkloads = append(extractedWorkloads, nsWorkloads...)
				}
			}

			if totalWorkloads != tt.want {
				t.Errorf("WorkloadExtractor.Extract() got %d workloads, want %d", totalWorkloads, tt.want)
			}

			// Verify metadata
			if count, ok := result.Metadata["count"].(int); !ok {
				// Allow if want is 0 and count is not set (or set to 0)
				if !(tt.want == 0 && (result.Metadata["count"] == nil || result.Metadata["count"].(int) == 0)) {
					t.Errorf("WorkloadExtractor.Extract() metadata count is not int, got: %T", result.Metadata["count"])
				}
			} else if count != tt.want {
				t.Errorf("WorkloadExtractor.Extract() metadata count = %v, want %d", count, tt.want)
			}

			// Basic verification for the newly added types
			if totalWorkloads == 1 && tt.want == 1 { // only check details if one specific workload was expected and found
				w := extractedWorkloads[0]
				switch tt.name {
				case "valid statefulset":
					if w.Type != WorkloadTypeStatefulSet || w.Name != "test-statefulset" || w.Namespace != "test-ns" || w.ServiceAccount != "test-sa-sts" {
						t.Errorf("StatefulSet mismatch: got %+v", w)
					}
					if len(w.Containers) != 1 || w.Containers[0].Name != "main-container" {
						t.Errorf("StatefulSet container mismatch: got %+v", w.Containers)
					}
				case "valid daemonset":
					if w.Type != WorkloadTypeDaemonSet || w.Name != "test-daemonset" || w.Namespace != "test-ds-ns" || w.ServiceAccount != "test-sa-ds" {
						t.Errorf("DaemonSet mismatch: got %+v", w)
					}
					if len(w.Containers) != 1 || w.Containers[0].Name != "ds-container" {
						t.Errorf("DaemonSet container mismatch: got %+v", w.Containers)
					}
				case "valid job":
					if w.Type != WorkloadTypeJob || w.Name != "test-job" || w.Namespace != "test-job-ns" || w.ServiceAccount != "test-sa-job" {
						t.Errorf("Job mismatch: got %+v", w)
					}
					if len(w.Containers) != 1 || w.Containers[0].Name != "job-container" {
						t.Errorf("Job container mismatch: got %+v", w.Containers)
					}
				case "valid cronjob":
					if w.Type != WorkloadTypeCronJob || w.Name != "test-cronjob" || w.Namespace != "test-cj-ns" || w.ServiceAccount != "test-sa-cj" {
						t.Errorf("CronJob mismatch: got %+v", w)
					}
					if len(w.Containers) != 1 || w.Containers[0].Name != "cj-container" {
						t.Errorf("CronJob container mismatch: got %+v", w.Containers)
					}
				}
			}
		})
	}
}
