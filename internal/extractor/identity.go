package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// Identity represents a service account identity
type Identity struct {
	// Name is the name of the service account
	Name string `json:"name"`
	// Namespace is the namespace where the service account exists
	Namespace string `json:"namespace"`
	// AutomountToken indicates if the service account automatically mounts API credentials
	AutomountToken bool `json:"automountToken"`
	// Secrets are the secrets associated with this service account
	Secrets []string `json:"secrets,omitempty"`
	// ImagePullSecrets are the image pull secrets associated with this service account
	ImagePullSecrets []string `json:"imagePullSecrets,omitempty"`
	// Labels are the labels attached to the service account
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations are the annotations attached to the service account
	Annotations map[string]string `json:"annotations,omitempty"`
}

// IdentityExtractor implements Extractor for ServiceAccount resources
type IdentityExtractor struct {
	opts    *Options
	scheme  *runtime.Scheme
	decoder runtime.Decoder
}

// NewIdentityExtractor creates a new IdentityExtractor
func NewIdentityExtractor(opts *Options) *IdentityExtractor {
	if opts == nil {
		opts = DefaultOptions()
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))

	decoder := serializer.NewCodecFactory(scheme).UniversalDeserializer()

	return &IdentityExtractor{
		opts:    opts,
		scheme:  scheme,
		decoder: decoder,
	}
}

// Extract processes the manifests and returns structured identity data
func (e *IdentityExtractor) Extract(ctx context.Context, manifests []*renderer.Manifest) (*Result, error) {
	if err := e.Validate(manifests); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	var identities []Identity

	for _, manifest := range manifests {
		// Try to decode as ServiceAccount
		obj, gvk, err := e.decoder.Decode(manifest.Raw, nil, nil)
		if err != nil {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("failed to decode manifest: %w", err)
			}
			continue
		}

		// Check if it's a ServiceAccount
		if gvk.Kind != "ServiceAccount" {
			continue
		}

		sa, ok := obj.(*corev1.ServiceAccount)
		if !ok {
			continue
		}

		// Convert ServiceAccount to Identity
		identity := Identity{
			Name:           sa.Name,
			Namespace:      sa.Namespace,
			AutomountToken: sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken,
			Labels:         sa.Labels,
			Annotations:    sa.Annotations,
		}

		// Extract secret names
		for _, secret := range sa.Secrets {
			identity.Secrets = append(identity.Secrets, secret.Name)
		}

		// Extract image pull secret names
		for _, secret := range sa.ImagePullSecrets {
			identity.ImagePullSecrets = append(identity.ImagePullSecrets, secret.Name)
		}

		identities = append(identities, identity)
	}

	result := NewResult()
	result.Data = make(map[string]interface{})
	identityMap := make(map[string]map[string]Identity)

	for _, identity := range identities {
		if _, exists := identityMap[identity.Name]; !exists {
			identityMap[identity.Name] = make(map[string]Identity)
		}
		identityMap[identity.Name][identity.Namespace] = identity
	}

	result.Data["identities"] = identityMap
	result.Metadata["count"] = len(identities)

	return result, nil
}

// Validate checks if the manifests can be processed
func (e *IdentityExtractor) Validate(manifests []*renderer.Manifest) error {
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
func (e *IdentityExtractor) SetOptions(opts *Options) {
	if opts != nil {
		e.opts = opts
	}
}

// GetOptions returns the current options
func (e *IdentityExtractor) GetOptions() *Options {
	return e.opts
}
