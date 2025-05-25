package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// WorkloadType represents the type of Kubernetes workload
type WorkloadType string

const (
	WorkloadTypePod         WorkloadType = "Pod"
	WorkloadTypeDeployment  WorkloadType = "Deployment"
	WorkloadTypeStatefulSet WorkloadType = "StatefulSet"
	WorkloadTypeReplicaSet  WorkloadType = "ReplicaSet"
	WorkloadTypeDaemonSet   WorkloadType = "DaemonSet"
	WorkloadTypeJob         WorkloadType = "Job"
	WorkloadTypeCronJob     WorkloadType = "CronJob"
)

// Container represents a container within a workload
type Container struct {
	Name            string                 `json:"name"`
	Image           string                 `json:"image"`
	SecurityContext map[string]interface{} `json:"securityContext,omitempty"`
	Resources       map[string]interface{} `json:"resources,omitempty"`
}

// Workload represents a Kubernetes workload
type Workload struct {
	Type            WorkloadType           `json:"type"`
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	ServiceAccount  string                 `json:"serviceAccount"`
	Labels          map[string]string      `json:"labels,omitempty"`
	Annotations     map[string]string      `json:"annotations,omitempty"`
	SecurityContext map[string]interface{} `json:"securityContext,omitempty"`
	Containers      []Container            `json:"containers"`
}

// WorkloadExtractor implements Extractor for workload resources
type WorkloadExtractor struct {
	opts    *Options
	scheme  *runtime.Scheme
	decoder runtime.Decoder
}

// NewWorkloadExtractor creates a new WorkloadExtractor
func NewWorkloadExtractor(opts *Options) *WorkloadExtractor {
	if opts == nil {
		opts = DefaultOptions()
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))

	decoder := serializer.NewCodecFactory(scheme).UniversalDeserializer()

	return &WorkloadExtractor{
		opts:    opts,
		scheme:  scheme,
		decoder: decoder,
	}
}

// Extract processes the manifests and returns structured workload data
func (e *WorkloadExtractor) Extract(ctx context.Context, manifests []*renderer.Manifest) (*Result, error) {
	if err := e.Validate(manifests); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	var workloads []Workload

	for _, manifest := range manifests {
		obj, gvk, err := e.decoder.Decode(manifest.Raw, nil, nil)
		if err != nil {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("failed to decode document: %w", err)
			}
			continue
		}

		var workload *Workload

		switch gvk.Kind {
		case string(WorkloadTypePod):
			pod := obj.(*corev1.Pod)
			workload = e.extractPodWorkload(pod)
		case string(WorkloadTypeDeployment):
			deploy := obj.(*appsv1.Deployment)
			workload = e.extractDeploymentWorkload(deploy)
		case string(WorkloadTypeStatefulSet):
			sts := obj.(*appsv1.StatefulSet)
			workload = e.extractStatefulSetWorkload(sts)
		case string(WorkloadTypeDaemonSet):
			ds := obj.(*appsv1.DaemonSet)
			workload = e.extractDaemonSetWorkload(ds)
		case string(WorkloadTypeJob):
			job := obj.(*batchv1.Job)
			workload = e.extractJobWorkload(job)
		case string(WorkloadTypeCronJob):
			cronJob := obj.(*batchv1.CronJob)
			workload = e.extractCronJobWorkload(cronJob)
		default:
			continue
		}

		if workload != nil {
			workloads = append(workloads, *workload)
		}
	}

	result := NewResult()
	result.Raw = workloads
	result.Metadata["count"] = len(workloads)

	return result, nil
}

func (e *WorkloadExtractor) extractPodWorkload(pod *corev1.Pod) *Workload {
	workload := &Workload{
		Type:            WorkloadTypePod,
		Name:            pod.Name,
		Namespace:       pod.Namespace,
		ServiceAccount:  pod.Spec.ServiceAccountName,
		Labels:          pod.Labels,
		Annotations:     pod.Annotations,
		SecurityContext: toMap(pod.Spec.SecurityContext),
	}

	for _, c := range pod.Spec.Containers {
		container := Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: toMap(c.SecurityContext),
			Resources:       toMap(c.Resources),
		}
		workload.Containers = append(workload.Containers, container)
	}

	return workload
}

func (e *WorkloadExtractor) extractDeploymentWorkload(deploy *appsv1.Deployment) *Workload {
	workload := &Workload{
		Type:            WorkloadTypeDeployment,
		Name:            deploy.Name,
		Namespace:       deploy.Namespace,
		ServiceAccount:  deploy.Spec.Template.Spec.ServiceAccountName,
		Labels:          deploy.Labels,
		Annotations:     deploy.Annotations,
		SecurityContext: toMap(deploy.Spec.Template.Spec.SecurityContext),
	}

	for _, c := range deploy.Spec.Template.Spec.Containers {
		container := Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: toMap(c.SecurityContext),
			Resources:       toMap(c.Resources),
		}
		workload.Containers = append(workload.Containers, container)
	}

	return workload
}

func (e *WorkloadExtractor) extractStatefulSetWorkload(sts *appsv1.StatefulSet) *Workload {
	workload := &Workload{
		Type:            WorkloadTypeStatefulSet,
		Name:            sts.Name,
		Namespace:       sts.Namespace,
		ServiceAccount:  sts.Spec.Template.Spec.ServiceAccountName,
		Labels:          sts.Labels,
		Annotations:     sts.Annotations,
		SecurityContext: toMap(sts.Spec.Template.Spec.SecurityContext),
	}

	for _, c := range sts.Spec.Template.Spec.Containers {
		container := Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: toMap(c.SecurityContext),
			Resources:       toMap(c.Resources),
		}
		workload.Containers = append(workload.Containers, container)
	}

	return workload
}

func (e *WorkloadExtractor) extractDaemonSetWorkload(ds *appsv1.DaemonSet) *Workload {
	workload := &Workload{
		Type:            WorkloadTypeDaemonSet,
		Name:            ds.Name,
		Namespace:       ds.Namespace,
		ServiceAccount:  ds.Spec.Template.Spec.ServiceAccountName,
		Labels:          ds.Labels,
		Annotations:     ds.Annotations,
		SecurityContext: toMap(ds.Spec.Template.Spec.SecurityContext),
	}

	for _, c := range ds.Spec.Template.Spec.Containers {
		container := Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: toMap(c.SecurityContext),
			Resources:       toMap(c.Resources),
		}
		workload.Containers = append(workload.Containers, container)
	}

	return workload
}

func (e *WorkloadExtractor) extractJobWorkload(job *batchv1.Job) *Workload {
	workload := &Workload{
		Type:            WorkloadTypeJob,
		Name:            job.Name,
		Namespace:       job.Namespace,
		ServiceAccount:  job.Spec.Template.Spec.ServiceAccountName,
		Labels:          job.Labels,
		Annotations:     job.Annotations,
		SecurityContext: toMap(job.Spec.Template.Spec.SecurityContext),
	}

	for _, c := range job.Spec.Template.Spec.Containers {
		container := Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: toMap(c.SecurityContext),
			Resources:       toMap(c.Resources),
		}
		workload.Containers = append(workload.Containers, container)
	}

	return workload
}

func (e *WorkloadExtractor) extractCronJobWorkload(cronJob *batchv1.CronJob) *Workload {
	workload := &Workload{
		Type:            WorkloadTypeCronJob,
		Name:            cronJob.Name,
		Namespace:       cronJob.Namespace,
		ServiceAccount:  cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		Labels:          cronJob.Labels,
		Annotations:     cronJob.Annotations,
		SecurityContext: toMap(cronJob.Spec.JobTemplate.Spec.Template.Spec.SecurityContext),
	}

	for _, c := range cronJob.Spec.JobTemplate.Spec.Template.Spec.Containers {
		container := Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: toMap(c.SecurityContext),
			Resources:       toMap(c.Resources),
		}
		workload.Containers = append(workload.Containers, container)
	}

	return workload
}

// Validate checks if the manifests can be processed
func (e *WorkloadExtractor) Validate(manifests []*renderer.Manifest) error {
	if len(manifests) == 0 {
		return ErrInvalidInput
	}

	for _, manifest := range manifests {
		if len(manifest.Raw) == 0 {
			return fmt.Errorf("%w: empty manifest", ErrInvalidInput)
		}
	}

	return nil
}

// SetOptions configures the extractor
func (e *WorkloadExtractor) SetOptions(opts *Options) {
	if opts != nil {
		e.opts = opts
	}
}

// GetOptions returns the current options
func (e *WorkloadExtractor) GetOptions() *Options {
	return e.opts
}

// toMap converts any struct to a map[string]interface{}
func toMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	result, err := runtime.DefaultUnstructuredConverter.ToUnstructured(v)
	if err != nil {
		return nil
	}
	return result
}
