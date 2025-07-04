package formatter

import "github.com/alevsk/rbac-scope/internal/policyevaluation"

// Type represents the type of formatter
type Type string

const (
	// TypeJSON formats data as JSON
	TypeJSON Type = "json"
	// TypeYAML formats data as YAML
	TypeYAML Type = "yaml"
	// TypeTable formats data as a table
	TypeTable Type = "table"
	// TypeMarkdown formats data as markdown
	TypeMarkdown Type = "markdown"
)

// JSON implements JSON formatting
type JSON struct {
	opts *Options
}

// YAML implements YAML formatting
type YAML struct {
	opts *Options
}

// Table implements table formatting
type Table struct {
	opts *Options
}

// Markdown implements markdown formatting
type Markdown struct {
	opts *Options
}

type SAIdentityEntry struct {
	ServiceAccountName string   `json:"serviceAccountName" yaml:"serviceAccountName"`
	Namespace          string   `json:"namespace" yaml:"namespace"`
	AutomountToken     bool     `json:"automountToken" yaml:"automountToken"`
	Secrets            []string `json:"secrets" yaml:"secrets"`
	ImagePullSecrets   []string `json:"imagePullSecrets" yaml:"imagePullSecrets"`
}

type SARoleBindingEntry struct {
	ServiceAccountName string                    `json:"serviceAccountName" yaml:"serviceAccountName"`
	Namespace          string                    `json:"namespace" yaml:"namespace"`
	RoleType           string                    `json:"roleType" yaml:"roleType"`
	RoleName           string                    `json:"roleName" yaml:"roleName"`
	APIGroup           string                    `json:"apiGroup" yaml:"apiGroup"`
	Resource           string                    `json:"resource" yaml:"resource"`
	ResourceName       string                    `json:"resourceName" yaml:"resourceName"`
	Verbs              []string                  `json:"verbs" yaml:"verbs"`
	RiskLevel          string                    `json:"riskLevel" yaml:"riskLevel"`
	Tags               policyevaluation.RiskTags `json:"tags" yaml:"tags"`
	MatchedRiskRules   []SARoleBindingRiskRule   `json:"matchedRiskRules" yaml:"matchedRiskRules"`
}

type SARoleBindingRiskRule struct {
	ID   int64  `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
	Link string `json:"link" yaml:"link"`
}

type SAWorkloadEntry struct {
	ServiceAccountName string `json:"serviceAccountName" yaml:"serviceAccountName"`
	Namespace          string `json:"namespace" yaml:"namespace"`
	WorkloadType       string `json:"workloadType" yaml:"workloadType"`
	WorkloadName       string `json:"workloadName" yaml:"workloadName"`
	ContainerName      string `json:"containerName" yaml:"containerName"`
	Image              string `json:"image" yaml:"image"`
}

type Metadata struct {
	Version   string                 `json:"version"`
	Name      string                 `json:"name"`
	Source    string                 `json:"source"`
	Timestamp int64                  `json:"timestamp"`
	Extra     map[string]interface{} `json:"extra,omitempty" yaml:"extra,omitempty"`
}

type ParsedData struct {
	Metadata     *Metadata            `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	IdentityData []SAIdentityEntry    `json:"serviceAccountData" yaml:"serviceAccountData"`
	RBACData     []SARoleBindingEntry `json:"serviceAccountPermissions" yaml:"serviceAccountPermissions"`
	WorkloadData []SAWorkloadEntry    `json:"serviceAccountWorkloads" yaml:"serviceAccountWorkloads"`
}
