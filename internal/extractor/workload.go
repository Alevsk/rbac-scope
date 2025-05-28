package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
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
	opts *Options
}

// NewWorkloadExtractor creates a new WorkloadExtractor
func NewWorkloadExtractor(opts *Options) *WorkloadExtractor {
	if opts == nil {
		opts = DefaultOptions()
	}

	return &WorkloadExtractor{
		opts: opts,
	}
}

// Extract processes the manifests and returns structured workload data
func (e *WorkloadExtractor) Extract(ctx context.Context, manifests []*renderer.Manifest) (*Result, error) {
	if err := e.Validate(manifests); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	var workloads []Workload

	for _, manifest := range manifests {
		// Get the kind of workload
		kind, ok := manifest.Content["kind"].(string)
		if !ok {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("missing kind in manifest")
			}
			continue
		}

		// Get metadata
		metadata, ok := manifest.Content["metadata"].(map[string]interface{})
		if !ok {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("invalid metadata in manifest")
			}
			continue
		}

		// Get spec
		spec, ok := manifest.Content["spec"].(map[string]interface{})
		if !ok {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("invalid spec in manifest")
			}
			continue
		}

		var workload *Workload

		switch kind {
		case string(WorkloadTypePod):
			workload = e.extractPodWorkload(metadata, spec)
		case string(WorkloadTypeDeployment):
			workload = e.extractDeploymentWorkload(metadata, spec)
		case string(WorkloadTypeStatefulSet):
			workload = e.extractStatefulSetWorkload(metadata, spec)
		case string(WorkloadTypeDaemonSet):
			workload = e.extractDaemonSetWorkload(metadata, spec)
		case string(WorkloadTypeJob):
			workload = e.extractJobWorkload(metadata, spec)
		case string(WorkloadTypeCronJob):
			workload = e.extractCronJobWorkload(metadata, spec)
		default:
			continue
		}

		if workload != nil {
			workloads = append(workloads, *workload)
		}
	}

	result := NewResult()
	result.Data = make(map[string]interface{})
	workloadMap := make(map[string]map[string][]Workload)

	// Group workloads by ServiceAccount and Namespace
	for _, workload := range workloads {
		if _, exists := workloadMap[workload.ServiceAccount]; !exists {
			workloadMap[workload.ServiceAccount] = make(map[string][]Workload)
		}
		workloadMap[workload.ServiceAccount][workload.Namespace] = append(
			workloadMap[workload.ServiceAccount][workload.Namespace],
			workload,
		)
	}

	result.Data["workloads"] = workloadMap
	result.Metadata["count"] = len(workloads)

	return result, nil
}

func (e *WorkloadExtractor) extractPodWorkload(metadata, spec map[string]interface{}) *Workload {
	workload := &Workload{
		Type:            WorkloadTypePod,
		Name:            metadata["name"].(string),
		Namespace:       metadata["namespace"].(string),
		ServiceAccount:  getStringValue(spec, "serviceAccountName"),
		Labels:          toStringMap(metadata["labels"]),
		Annotations:     toStringMap(metadata["annotations"]),
		SecurityContext: getMap(spec, "securityContext"),
	}

	containers, ok := spec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			containerMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			container := Container{
				Name:            getStringValue(containerMap, "name"),
				Image:           getStringValue(containerMap, "image"),
				SecurityContext: getMap(containerMap, "securityContext"),
				Resources:       getMap(containerMap, "resources"),
			}
			workload.Containers = append(workload.Containers, container)
		}
	}

	return workload
}

func (e *WorkloadExtractor) extractDeploymentWorkload(metadata, spec map[string]interface{}) *Workload {
	templateSpec := getTemplateSpec(spec)
	if templateSpec == nil {
		return nil
	}

	workload := &Workload{
		Type:            WorkloadTypeDeployment,
		Name:            metadata["name"].(string),
		Namespace:       metadata["namespace"].(string),
		ServiceAccount:  getStringValue(templateSpec, "serviceAccountName"),
		Labels:          toStringMap(metadata["labels"]),
		Annotations:     toStringMap(metadata["annotations"]),
		SecurityContext: getMap(templateSpec, "securityContext"),
	}

	containers, ok := templateSpec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			containerMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			container := Container{
				Name:            getStringValue(containerMap, "name"),
				Image:           getStringValue(containerMap, "image"),
				SecurityContext: getMap(containerMap, "securityContext"),
				Resources:       getMap(containerMap, "resources"),
			}
			workload.Containers = append(workload.Containers, container)
		}
	}

	return workload
}

func (e *WorkloadExtractor) extractStatefulSetWorkload(metadata, spec map[string]interface{}) *Workload {
	templateSpec := getTemplateSpec(spec)
	if templateSpec == nil {
		return nil
	}

	workload := &Workload{
		Type:            WorkloadTypeStatefulSet,
		Name:            metadata["name"].(string),
		Namespace:       metadata["namespace"].(string),
		ServiceAccount:  getStringValue(templateSpec, "serviceAccountName"),
		Labels:          toStringMap(metadata["labels"]),
		Annotations:     toStringMap(metadata["annotations"]),
		SecurityContext: getMap(templateSpec, "securityContext"),
	}

	containers, ok := templateSpec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			containerMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			container := Container{
				Name:            getStringValue(containerMap, "name"),
				Image:           getStringValue(containerMap, "image"),
				SecurityContext: getMap(containerMap, "securityContext"),
				Resources:       getMap(containerMap, "resources"),
			}
			workload.Containers = append(workload.Containers, container)
		}
	}

	return workload
}

func (e *WorkloadExtractor) extractDaemonSetWorkload(metadata, spec map[string]interface{}) *Workload {
	templateSpec := getTemplateSpec(spec)
	if templateSpec == nil {
		return nil
	}

	workload := &Workload{
		Type:            WorkloadTypeDaemonSet,
		Name:            metadata["name"].(string),
		Namespace:       metadata["namespace"].(string),
		ServiceAccount:  getStringValue(templateSpec, "serviceAccountName"),
		Labels:          toStringMap(metadata["labels"]),
		Annotations:     toStringMap(metadata["annotations"]),
		SecurityContext: getMap(templateSpec, "securityContext"),
	}

	containers, ok := templateSpec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			containerMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			container := Container{
				Name:            getStringValue(containerMap, "name"),
				Image:           getStringValue(containerMap, "image"),
				SecurityContext: getMap(containerMap, "securityContext"),
				Resources:       getMap(containerMap, "resources"),
			}
			workload.Containers = append(workload.Containers, container)
		}
	}

	return workload
}

func (e *WorkloadExtractor) extractJobWorkload(metadata, spec map[string]interface{}) *Workload {
	templateSpec := getTemplateSpec(spec)
	if templateSpec == nil {
		return nil
	}

	workload := &Workload{
		Type:            WorkloadTypeJob,
		Name:            metadata["name"].(string),
		Namespace:       metadata["namespace"].(string),
		ServiceAccount:  getStringValue(templateSpec, "serviceAccountName"),
		Labels:          toStringMap(metadata["labels"]),
		Annotations:     toStringMap(metadata["annotations"]),
		SecurityContext: getMap(templateSpec, "securityContext"),
	}

	containers, ok := templateSpec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			containerMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			container := Container{
				Name:            getStringValue(containerMap, "name"),
				Image:           getStringValue(containerMap, "image"),
				SecurityContext: getMap(containerMap, "securityContext"),
				Resources:       getMap(containerMap, "resources"),
			}
			workload.Containers = append(workload.Containers, container)
		}
	}

	return workload
}

func (e *WorkloadExtractor) extractCronJobWorkload(metadata, spec map[string]interface{}) *Workload {
	jobTemplate, ok := spec["jobTemplate"].(map[string]interface{})
	if !ok {
		return nil
	}

	jobSpec, ok := jobTemplate["spec"].(map[string]interface{})
	if !ok {
		return nil
	}

	templateSpec := getTemplateSpec(jobSpec)
	if templateSpec == nil {
		return nil
	}

	workload := &Workload{
		Type:            WorkloadTypeCronJob,
		Name:            metadata["name"].(string),
		Namespace:       metadata["namespace"].(string),
		ServiceAccount:  getStringValue(templateSpec, "serviceAccountName"),
		Labels:          toStringMap(metadata["labels"]),
		Annotations:     toStringMap(metadata["annotations"]),
		SecurityContext: getMap(templateSpec, "securityContext"),
	}

	containers, ok := templateSpec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			containerMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			container := Container{
				Name:            getStringValue(containerMap, "name"),
				Image:           getStringValue(containerMap, "image"),
				SecurityContext: getMap(containerMap, "securityContext"),
				Resources:       getMap(containerMap, "resources"),
			}
			workload.Containers = append(workload.Containers, container)
		}
	}

	return workload
}

// Validate checks if the manifests can be processed
func (e *WorkloadExtractor) Validate(manifests []*renderer.Manifest) error {
	if len(manifests) == 0 {
		return ErrInvalidInput
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

// getStringValue returns the string value of a key in a map
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// getMap returns the map value of a key in a map
func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if val, ok := m[key].(map[string]interface{}); ok {
		return val
	}
	return nil
}

// toStringMap converts a map to a map of strings
func toStringMap(v interface{}) map[string]string {
	if v == nil {
		return nil
	}

	if m, ok := v.(map[string]interface{}); ok {
		result := make(map[string]string)
		for k, v := range m {
			if str, ok := v.(string); ok {
				result[k] = str
			}
		}
		return result
	}

	return nil
}

// getTemplateSpec returns the template spec from a workload spec
func getTemplateSpec(spec map[string]interface{}) map[string]interface{} {
	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		return nil
	}

	templateSpec, ok := template["spec"].(map[string]interface{})
	if !ok {
		return nil
	}

	return templateSpec
}
