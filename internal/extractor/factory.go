package extractor

import "fmt"

// defaultExtractorFactory implements ExtractorFactory
type defaultExtractorFactory struct{}

// NewExtractorFactory creates a new default extractor factory
func NewExtractorFactory() ExtractorFactory {
	return &defaultExtractorFactory{}
}

// NewExtractor creates a new extractor of the specified type
func (f *defaultExtractorFactory) NewExtractor(t ExtractorType, opts *Options) (Extractor, error) {
	if opts == nil {
		opts = DefaultOptions()
	}

	const (
		ExtractorTypeIdentity ExtractorType = "identity"
		ExtractorTypeWorkload ExtractorType = "workload"
		ExtractorTypeRBAC     ExtractorType = "rbac"
	)

	switch t {
	case ExtractorTypeIdentity:
		return NewIdentityExtractor(opts), nil
	case ExtractorTypeWorkload:
		return NewWorkloadExtractor(opts), nil
	case ExtractorTypeRBAC:
		return NewRBACExtractor(opts), nil
	default:
		return nil, fmt.Errorf("unknown extractor type: %s", t)
	}
}
