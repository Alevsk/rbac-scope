package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
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
	opts *Options
}

// NewIdentityExtractor creates a new IdentityExtractor
func NewIdentityExtractor(opts *Options) *IdentityExtractor {
	if opts == nil {
		opts = DefaultOptions()
	}

	return &IdentityExtractor{
		opts: opts,
	}
}

// Extract processes the manifests and returns structured identity data
func (e *IdentityExtractor) Extract(ctx context.Context, manifests []*renderer.Manifest) (*Result, error) {
	if err := e.Validate(manifests); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	var identities []Identity

	for _, manifest := range manifests {
		// Check if it's a ServiceAccount
		kind, ok := manifest.Content["kind"].(string)
		if !ok {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("missing kind field in manifest")
			}
			continue
		}
		if kind != "ServiceAccount" {
			continue
		}

		metadata, ok := manifest.Content["metadata"].(map[string]interface{})
		if !ok {
			if e.opts.StrictParsing {
				return nil, fmt.Errorf("invalid metadata in ServiceAccount manifest")
			}
			continue
		}

		// Convert ServiceAccount to Identity
		identity := Identity{
			Name:        metadata["name"].(string),
			Namespace:   metadata["namespace"].(string),
			Labels:      make(map[string]string),
			Annotations: make(map[string]string),
		}

		// Handle labels
		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			for k, v := range labels {
				identity.Labels[k] = v.(string)
			}
		}

		// Handle annotations
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			for k, v := range annotations {
				identity.Annotations[k] = v.(string)
			}
		}

		// Handle automountServiceAccountToken
		if automount, ok := manifest.Content["automountServiceAccountToken"].(bool); ok {
			identity.AutomountToken = automount
		}

		// Extract secret names
		if secrets, ok := manifest.Content["secrets"].([]interface{}); ok {
			for _, secret := range secrets {
				if secretMap, ok := secret.(map[string]interface{}); ok {
					if name, ok := secretMap["name"].(string); ok {
						identity.Secrets = append(identity.Secrets, name)
					}
				}
			}
		}

		// Extract image pull secret names
		if imagePullSecrets, ok := manifest.Content["imagePullSecrets"].([]interface{}); ok {
			for _, secret := range imagePullSecrets {
				if secretMap, ok := secret.(map[string]interface{}); ok {
					if name, ok := secretMap["name"].(string); ok {
						identity.ImagePullSecrets = append(identity.ImagePullSecrets, name)
					}
				}
			}
		}

		identities = append(identities, identity)
	}

	result := NewResult()
	result.Data = make(map[string]interface{})
	identityMap := make(map[string]map[string]Identity)

	for _, identity := range identities {
		if _, exists := identityMap[identity.Namespace]; !exists {
			identityMap[identity.Namespace] = make(map[string]Identity)
		}
		identityMap[identity.Namespace][identity.Name] = identity
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
		if manifest.Content == nil {
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
