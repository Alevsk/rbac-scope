package extractor

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

func TestWorkloadExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     int
		wantErr  bool
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
			e := NewWorkloadExtractor(nil)
			// Split manifest into multiple documents if needed
			docs := bytes.Split([]byte(tt.manifest), []byte("\n---\n"))
			var manifests []*renderer.Manifest
			for _, doc := range docs {
				manifests = append(manifests, &renderer.Manifest{Raw: doc})
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

func TestWorkloadExtractor_Validate(t *testing.T) {
	e := NewWorkloadExtractor(nil)

	if err := e.Validate(nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("Validate(nil) error = %v, want %v", err, ErrInvalidInput)
	}

	err := e.Validate([]*renderer.Manifest{{}})
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Errorf("Validate(empty) error = %v, want %v", err, ErrInvalidInput)
	}

	if err := e.Validate([]*renderer.Manifest{{Raw: []byte("kind: Pod")}}); err != nil {
		t.Errorf("Validate(valid) unexpected error: %v", err)
	}
}

func TestWorkloadExtractor_SetGetOptions(t *testing.T) {
	e := NewWorkloadExtractor(nil)
	def := e.GetOptions()
	custom := &Options{StrictParsing: false}
	e.SetOptions(custom)
	if e.GetOptions() != custom {
		t.Errorf("GetOptions did not return custom value")
	}
	e.SetOptions(nil)
	if e.GetOptions() != custom {
		t.Errorf("SetOptions(nil) modified options")
	}
	if reflect.DeepEqual(def, custom) {
		t.Errorf("default and custom options unexpectedly equal")
	}
}

func TestWorkloadExtractor_Extract_NonStrict(t *testing.T) {
	e := NewWorkloadExtractor(nil)
	opts := e.GetOptions()
	opts.StrictParsing = false
	e.SetOptions(opts)
	manifests := []*renderer.Manifest{{Raw: []byte("invalid: [yaml")}}
	result, err := e.Extract(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Extract non strict error: %v", err)
	}
	workloads := result.Data["workloads"].(map[string]map[string][]Workload)
	if len(workloads) != 0 {
		t.Errorf("expected empty workloads, got %v", workloads)
	}
}

func TestWorkloadExtractor_extractPodWorkload(t *testing.T) {
	saName := "test"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: saName,
			Containers:         []corev1.Container{{Name: "c", Image: "img"}},
		},
	}
	e := NewWorkloadExtractor(nil)
	w := e.extractPodWorkload(pod)
	if w.Type != WorkloadTypePod || w.Name != "p" || w.Namespace != "ns" || w.ServiceAccount != saName {
		t.Errorf("unexpected workload %+v", w)
	}
	if len(w.Containers) != 1 || w.Containers[0].Name != "c" {
		t.Errorf("container not extracted correctly: %+v", w.Containers)
	}
}

func TestWorkloadExtractor_extractCronJobWorkload(t *testing.T) {
	cron := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "cj", Namespace: "ns"},
		Spec: batchv1.CronJobSpec{
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							ServiceAccountName: "sa",
							Containers:         []corev1.Container{{Name: "c"}},
						},
					},
				},
			},
		},
	}
	e := NewWorkloadExtractor(nil)
	w := e.extractCronJobWorkload(cron)
	if w.Type != WorkloadTypeCronJob || w.Name != "cj" || w.ServiceAccount != "sa" {
		t.Errorf("unexpected cronjob workload %+v", w)
	}
	if len(w.Containers) != 1 {
		t.Errorf("expected one container, got %d", len(w.Containers))
	}
}

func TestToMap(t *testing.T) {
	if toMap(nil) != nil {
		t.Errorf("toMap(nil) should return nil")
	}
	type simple struct {
		Field string `json:"field"`
	}
	m := toMap(simple{Field: "v"})
	if v, ok := m["field"]; !ok || v != "v" {
		t.Errorf("toMap(simple) = %v", m)
	}
}
