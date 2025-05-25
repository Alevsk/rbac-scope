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

	switch t {
	case ExtractorTypeIdentity:
		return NewIdentityExtractor(opts), nil
	case ExtractorTypeWorkload:
		// Will be implemented in E503
		return nil, fmt.Errorf("workload extractor not yet implemented")
	case ExtractorTypeRBAC:
		// Will be implemented in E504
		return nil, fmt.Errorf("rbac extractor not yet implemented")
	default:
		return nil, fmt.Errorf("unknown extractor type: %s", t)
	}
}
