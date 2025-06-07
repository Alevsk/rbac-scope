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
	APIServerDoS                 RiskTag = "APIServerDoS"
	APIServiceManipulation       RiskTag = "APIServiceManipulation"
	BackupAccess                 RiskTag = "BackupAccess"
	BindingToPrivilegedRole      RiskTag = "BindingToPrivilegedRole"
	CRDManipulation              RiskTag = "CRDManipulation"
	CSRApproval                  RiskTag = "CSRApproval"
	CSRCreation                  RiskTag = "CSRCreation"
	CertificateManagement        RiskTag = "CertificateManagement"
	ClusterAdminAccess           RiskTag = "ClusterAdminAccess"
	ClusterWideLogAccess         RiskTag = "ClusterWideLogAccess"
	ClusterWidePodAttach         RiskTag = "ClusterWidePodAttach"
	ClusterWidePodExec           RiskTag = "ClusterWidePodExec"
	ClusterWidePodPortForward    RiskTag = "ClusterWidePodPortForward"
	ClusterWideSecretAccess      RiskTag = "ClusterWideSecretAccess"
	CodeExecution                RiskTag = "CodeExecution"
	ConfigMapAccess              RiskTag = "ConfigMapAccess"
	ControllerRevisionTampering  RiskTag = "ControllerRevisionTampering"
	CredentialAccess             RiskTag = "CredentialAccess"
	DataExposure                 RiskTag = "DataExposure"
	DataLoss                     RiskTag = "DataLoss"
	Exfiltration                 RiskTag = "Exfiltration"
	Impersonation                RiskTag = "Impersonation"
	LateralMovement              RiskTag = "LateralMovement"
	LegacyWorkloadDisruption     RiskTag = "LegacyWorkloadDisruption"
	LogAccess                    RiskTag = "LogAccess"
	NamespaceAdmin               RiskTag = "NamespaceAdmin"
	NamespaceLifecycle           RiskTag = "NamespaceLifecycle"
	NetworkManipulation          RiskTag = "NetworkManipulation"
	NetworkPolicyManagement      RiskTag = "NetworkPolicyManagement"
	NodeAccess                   RiskTag = "NodeAccess"
	Persistence                  RiskTag = "Persistence"
	PodAttach                    RiskTag = "PodAttach"
	PodExec                      RiskTag = "PodExec"
	PodPortForward               RiskTag = "PodPortForward"
	PotentialPrivilegeEscalation RiskTag = "PotentialPrivilegeEscalation"
	PrivilegeEscalation          RiskTag = "PrivilegeEscalation" // More specific than EoP
	QuotaTampering               RiskTag = "QuotaTampering"
	RBACManipulation             RiskTag = "RBACManipulation"
	RBACQuery                    RiskTag = "RBACQuery"
	ResourceConfiguration        RiskTag = "ResourceConfiguration"
	ResourceCreation             RiskTag = "ResourceCreation"
	ResourceDeletion             RiskTag = "ResourceDeletion"
	ResourceModification         RiskTag = "ResourceModification"
	SecretAccess                 RiskTag = "SecretAccess"
	SelfPermissionReviewQuery  RiskTag = "SelfPermissionReviewQuery"
	ServiceExposure              RiskTag = "ServiceExposure"
	StorageDetailsDisclosure     RiskTag = "StorageDetailsDisclosure"
	StorageManipulation          RiskTag = "StorageManipulation"
	TokenCreation                RiskTag = "TokenCreation"
	WebhookManipulation          RiskTag = "WebhookManipulation"
	WebhookReconnaissance        RiskTag = "WebhookReconnaissance"
	WildcardPermission           RiskTag = "WildcardPermission"
	WorkloadDeployment           RiskTag = "WorkloadDeployment"
	WorkloadExecution            RiskTag = "WorkloadExecution"
	WorkloadLifecycle            RiskTag = "WorkloadLifecycle"
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
