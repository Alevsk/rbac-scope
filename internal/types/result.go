package types

// Manifest represents a single YAML manifest
type Manifest struct {
	// Name of the manifest
	Name string `json:"name"`
	// Content is the parsed YAML content
	Content map[string]interface{} `json:"content"`
	// Raw is the original YAML content
	Raw []byte `json:"raw,omitempty"`
	// Metadata contains additional information about the manifest
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ExtractedData represents structured data extracted from manifests
type ExtractedData struct {
	// Data contains the structured extracted data
	Data map[string]interface{} `json:"data"`
	// Metadata contains additional information about the extraction
	Metadata map[string]interface{} `json:"metadata"`
}

// Result represents a unified result type for all operations
type Result struct {
	// Basic information
	Version   string `json:"version"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Success   bool   `json:"success"`
	Error     error  `json:"error"`
	Timestamp int64  `json:"timestamp"`

	// Manifest data (from renderer)
	Manifests []*Manifest `json:"manifests,omitempty"`
	Warnings  []string    `json:"warnings,omitempty"`

	// Extracted data (from extractors)
	IdentityData *ExtractedData `json:"identity_data,omitempty"`
	WorkloadData *ExtractedData `json:"workload_data,omitempty"`
	RBACData     *ExtractedData `json:"rbac_data,omitempty"`

	// Formatted output
	OutputFormatted string `json:"output_formatted,omitempty"`

	// Additional data
	Extra map[string]interface{} `json:"extra,omitempty"`
}
