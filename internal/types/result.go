package types

import "github.com/alevsk/rbac-ops/internal/extractor"

// Result represents the outcome of an ingestion operation
type Result struct {
	Version   string `json:"version"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Success   bool   `json:"success"`
	Error     error  `json:"error"`
	Timestamp int64  `json:"timestamp"`
	// Extracted data from each extractor
	IdentityData *extractor.Result `json:"identity_data"`
	WorkloadData *extractor.Result `json:"workload_data"`
	RBACData     *extractor.Result `json:"rbac_data"`
	// Formatted output string
	OutputFormatted string `json:"output_formatted,omitempty"`
}
