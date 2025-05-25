package extractor

// ExtractorType represents the type of extractor
type ExtractorType string

const (
	// ExtractorTypeIdentity extracts ServiceAccount and identity information
	ExtractorTypeIdentity ExtractorType = "identity"
	// ExtractorTypeWorkload extracts workload information
	ExtractorTypeWorkload ExtractorType = "workload"
	// ExtractorTypeRBAC extracts RBAC information
	ExtractorTypeRBAC ExtractorType = "rbac"
)

// ExtractorFactory creates new extractors based on type
type ExtractorFactory interface {
	// NewExtractor creates a new extractor of the specified type
	NewExtractor(t ExtractorType, opts *Options) (Extractor, error)
}
