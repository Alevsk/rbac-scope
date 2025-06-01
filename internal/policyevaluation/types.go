package policyevaluation

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type RiskLevel int

const (
	RiskLevelLow      RiskLevel = iota // namespaced scoped with limited access to a specific API group and namespace resources and verbs
	RiskLevelMedium                    // namespaced scoped with access to sensitive API groups and resources
	RiskLevelHigh                      // cluster-wide access across all namespaces but limited to a specific API group
	RiskLevelCritical                  // cluster-wide access across all namespaces and all API groups
)

// UnmarshalYAML implements the yaml.Unmarshaler interface for RiskLevel
func (rl *RiskLevel) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return err
	}

	switch str {
	case "RiskLevelLow":
		*rl = RiskLevelLow
	case "RiskLevelMedium":
		*rl = RiskLevelMedium
	case "RiskLevelHigh":
		*rl = RiskLevelHigh
	case "RiskLevelCritical":
		*rl = RiskLevelCritical
	default:
		return fmt.Errorf("invalid risk level: %s", str)
	}
	return nil
}

// Implement Stringer for RiskLevel
func (rl RiskLevel) String() string {
	switch rl {
	case RiskLevelLow:
		return "Low"
	case RiskLevelMedium:
		return "Medium"
	case RiskLevelHigh:
		return "High"
	case RiskLevelCritical:
		return "Critical"
	default:
		return ""
	}
}

type RiskTag string

// Implement Stringer for RiskTag
func (rt RiskTag) String() string {
	return string(rt)
}

type RiskTags []RiskTag

func (rs RiskTags) Strings() []string {
	out := []string{}
	for _, v := range rs {
		out = append(out, v.String())
	}
	return out
}

func (rs RiskTags) String() string {
	return strings.Join(rs.Strings(), ",")
}

func (rs RiskTags) StringSlice(limit int) []string {
	tags := make([]string, 0, limit)
	for i, tag := range rs {
		if i >= limit {
			if i == limit {
				tags = append(tags, fmt.Sprintf("(%d more)", len(rs)-limit))
			}
			break
		}
		tags = append(tags, tag.String())
	}
	return tags
}

const (
	// STRIDE Categories
	Spoofing              RiskTag = "Spoofing"
	Tampering             RiskTag = "Tampering"
	Repudiation           RiskTag = "Repudiation" // Generally harder to map directly
	InformationDisclosure RiskTag = "InformationDisclosure"
	DenialOfService       RiskTag = "DenialOfService"
	ElevationOfPrivilege  RiskTag = "ElevationOfPrivilege"

	// Specific Threat Types
	PrivilegeEscalation          RiskTag = "PrivilegeEscalation" // More specific than EoP
	PotentialPrivilegeEscalation RiskTag = "PotentialPrivilegeEscalation"
	LateralMovement              RiskTag = "LateralMovement"
	DataExposure                 RiskTag = "DataExposure"
	DataLoss                     RiskTag = "DataLoss"
	CodeExecution                RiskTag = "CodeExecution"
	CredentialAccess             RiskTag = "CredentialAccess"
	Impersonation                RiskTag = "Impersonation"
	Persistence                  RiskTag = "Persistence"
	Exfiltration                 RiskTag = "Exfiltration"
	ClusterAdminAccess           RiskTag = "ClusterAdminAccess"
	NamespaceAdmin               RiskTag = "NamespaceAdmin"
	WorkloadExecution            RiskTag = "WorkloadExecution"
	WorkloadLifecycle            RiskTag = "WorkloadLifecycle"
	NetworkManipulation          RiskTag = "NetworkManipulation"
	StorageManipulation          RiskTag = "StorageManipulation"
	WebhookManipulation          RiskTag = "WebhookManipulation"
	CRDManipulation              RiskTag = "CRDManipulation"
	APIServiceManipulation       RiskTag = "APIServiceManipulation"
	RBACManipulation             RiskTag = "RBACManipulation"
	RBACQuery                    RiskTag = "RBACQuery"
	SecretAccess                 RiskTag = "SecretAccess"
	ClusterWideSecretAccess      RiskTag = "ClusterWideSecretAccess"
	ConfigMapAccess              RiskTag = "ConfigMapAccess"
	NodeAccess                   RiskTag = "NodeAccess"
	PodExec                      RiskTag = "PodExec"
	ClusterWidePodExec           RiskTag = "ClusterWidePodExec"
	PodAttach                    RiskTag = "PodAttach"
	ClusterWidePodAttach         RiskTag = "ClusterWidePodAttach"
	PodPortForward               RiskTag = "PodPortForward"
	ClusterWidePodPortForward    RiskTag = "ClusterWidePodPortForward"
	LogAccess                    RiskTag = "LogAccess"
	ClusterWideLogAccess         RiskTag = "ClusterWideLogAccess"
	TokenCreation                RiskTag = "TokenCreation"
	CSRApproval                  RiskTag = "CSRApproval"
	CSRCreation                  RiskTag = "CSRCreation"
	NamespaceLifecycle           RiskTag = "NamespaceLifecycle"
	BindingToPrivilegedRole      RiskTag = "BindingToPrivilegedRole"
	WildcardPermission           RiskTag = "WildcardPermission"
	CertificateManagement        RiskTag = "CertificateManagement"
	WorkloadDeployment           RiskTag = "WorkloadDeployment"
	NetworkPolicyManagement      RiskTag = "NetworkPolicyManagement"
	BackupAccess                 RiskTag = "BackupAccess"
	ResourceCreation             RiskTag = "ResourceCreation"
	ResourceModification         RiskTag = "ResourceModification"
	ResourceDeletion             RiskTag = "ResourceDeletion"
)

type RiskRule struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Category    string    `yaml:"category"`
	RiskLevel   RiskLevel `yaml:"risk_level"`
	APIGroups   []string  `yaml:"api_groups"`
	RoleType    string    `yaml:"role_type"`
	Resources   []string  `yaml:"resources"`
	Verbs       []string  `yaml:"verbs"`
	Tags        RiskTags  `yaml:"tags"`
}

type Policy struct {
	Namespace string   `json:"namespace" yaml:"namespace"`
	RoleType  string   `json:"roleType" yaml:"roleType"`
	RoleName  string   `json:"roleName" yaml:"roleName"`
	APIGroup  string   `json:"apiGroup" yaml:"apiGroup"`
	Resource  string   `json:"resource" yaml:"resource"`
	Verbs     []string `json:"verbs" yaml:"verbs"`
}
