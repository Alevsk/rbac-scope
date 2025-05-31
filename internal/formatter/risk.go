package formatter

import (
	"sort"
)

// contains checks if a string slice contains a specific value
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

type RiskLevel int

const (
	RiskLevelLow      RiskLevel = iota // namespaced scoped with limited access to a specific API group and namespace resources and verbs
	RiskLevelMedium                    // namespaced scoped with access to sensitive API groups and resources
	RiskLevelHigh                      // cluster-wide access across all namespaces but limited to a specific API group
	RiskLevelCritical                  // cluster-wide access across all namespaces and all API groups
)

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

func (t RiskTag) String() string {
	return string(t)
}

type RiskRule struct {
	Description string
	Category    string // STRIDE Category
	RiskLevel   RiskLevel
	APIGroups   []string
	RoleType    string // "Role" or "ClusterRole"
	Resources   []string
	Verbs       []string
	Tags        []RiskTag
}

var RiskRules = []RiskRule{
	// --- Core API Group (v1) ---
	{
		Description: "Cluster-wide pod exec",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{}, // Core API group
		RoleType:    "ClusterRole",
		Resources:   []string{"pods/exec"},
		Verbs:       []string{"create"}, // "create" initiates exec, "get" is for streaming
		Tags:        []RiskTag{ClusterWidePodExec, CodeExecution, LateralMovement, ElevationOfPrivilege},
	},
	{
		Description: "Namespaced pod exec",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods/exec"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{PodExec, CodeExecution, LateralMovement, PotentialPrivilegeEscalation},
	},
	{
		Description: "Cluster-wide pod attach",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"pods/attach"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{ClusterWidePodAttach, CodeExecution, LateralMovement, ElevationOfPrivilege},
	},
	{
		Description: "Namespaced pod attach",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods/attach"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{PodAttach, CodeExecution, LateralMovement, PotentialPrivilegeEscalation},
	},
	{
		Description: "Cluster-wide pod port-forward",
		Category:    "Information Disclosure", // Can be used for lateral movement too
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"pods/portforward"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{ClusterWidePodPortForward, LateralMovement, NetworkManipulation},
	},
	{
		Description: "Namespaced pod port-forward",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods/portforward"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{PodPortForward, LateralMovement, NetworkManipulation},
	},
	{
		Description: "Create pods cluster-wide (potential for privileged pods)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"pods"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{WorkloadExecution, PrivilegeEscalation, LateralMovement, Persistence},
	},
	{
		Description: "Create pods in a namespace (potential for privileged pods)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{WorkloadExecution, PotentialPrivilegeEscalation, LateralMovement, Persistence},
	},
	{
		Description: "Update/Patch pods cluster-wide (can modify to privileged)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"pods"},
		Verbs:       []string{"update", "patch"},
		Tags:        []RiskTag{WorkloadExecution, PrivilegeEscalation, Tampering},
	},
	{
		Description: "Update/Patch pods in a namespace (can modify to privileged)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods"},
		Verbs:       []string{"update", "patch"},
		Tags:        []RiskTag{WorkloadExecution, PotentialPrivilegeEscalation, Tampering},
	},
	{
		Description: "Read secrets cluster-wide",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"secrets"},
		Verbs:       []string{"get", "list", "watch"},
		Tags:        []RiskTag{ClusterWideSecretAccess, CredentialAccess, DataExposure, InformationDisclosure},
	},
	{
		Description: "Read secrets in a namespace",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelCritical, // Secrets are critical even namespaced
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"secrets"},
		Verbs:       []string{"get", "list", "watch"},
		Tags:        []RiskTag{SecretAccess, CredentialAccess, DataExposure, InformationDisclosure},
	},
	{
		Description: "Modify secrets cluster-wide",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"secrets"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{ClusterWideSecretAccess, Tampering, PrivilegeEscalation, Persistence},
	},
	{
		Description: "Modify secrets in a namespace",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"secrets"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{SecretAccess, Tampering, PotentialPrivilegeEscalation, Persistence},
	},
	{
		Description: "Node proxy access (Kubelet API)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"nodes/proxy"},
		Verbs:       []string{"get", "create", "update", "patch", "delete"}, // All verbs are dangerous
		Tags:        []RiskTag{NodeAccess, ClusterAdminAccess, CodeExecution, LateralMovement, DataExposure, Tampering},
	},
	{
		Description: "Modify node configuration (labels, taints)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"nodes"},
		Verbs:       []string{"patch", "update"},
		Tags:        []RiskTag{NodeAccess, Tampering, PotentialPrivilegeEscalation, DenialOfService},
	},
	{
		Description: "Delete nodes",
		Category:    "Denial of Service",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"nodes"},
		Verbs:       []string{"delete", "deletecollection"},
		Tags:        []RiskTag{NodeAccess, DenialOfService, ResourceDeletion},
	},
	{
		Description: "Manage PersistentVolumes (cluster-wide storage manipulation)",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"persistentvolumes"},
		Verbs:       []string{"create", "update", "patch", "delete", "deletecollection"},
		Tags:        []RiskTag{StorageManipulation, DataExposure, DataLoss, DenialOfService, Tampering},
	},
	{
		Description: "Read pod logs cluster-wide",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"pods/log"},
		Verbs:       []string{"get"},
		Tags:        []RiskTag{ClusterWideLogAccess, InformationDisclosure, DataExposure},
	},
	{
		Description: "Read pod logs in a namespace",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods/log"},
		Verbs:       []string{"get"},
		Tags:        []RiskTag{LogAccess, InformationDisclosure, DataExposure},
	},
	{
		Description: "Manage ephemeral containers cluster-wide",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"pods/ephemeralcontainers"},
		Verbs:       []string{"update", "patch"},
		Tags:        []RiskTag{WorkloadExecution, CodeExecution, LateralMovement, Tampering, ElevationOfPrivilege},
	},
	{
		Description: "Manage ephemeral containers in a namespace",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"pods/ephemeralcontainers"},
		Verbs:       []string{"update", "patch"},
		Tags:        []RiskTag{WorkloadExecution, CodeExecution, LateralMovement, Tampering, PotentialPrivilegeEscalation},
	},
	{
		Description: "Read ConfigMaps cluster-wide",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"configmaps"},
		Verbs:       []string{"get", "list", "watch"},
		Tags:        []RiskTag{InformationDisclosure, ConfigMapAccess, DataExposure},
	},
	{
		Description: "Read ConfigMaps in a namespace",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"configmaps"},
		Verbs:       []string{"get", "list", "watch"},
		Tags:        []RiskTag{InformationDisclosure, ConfigMapAccess, DataExposure},
	},
	{
		Description: "Modify ConfigMaps cluster-wide",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"configmaps"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{Tampering, ConfigMapAccess, PotentialPrivilegeEscalation},
	},
	{
		Description: "Modify ConfigMaps in a namespace",
		Category:    "Tampering",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "Role",
		Resources:   []string{"configmaps"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{Tampering, ConfigMapAccess, PotentialPrivilegeEscalation},
	},
	{
		Description: "Delete namespaces",
		Category:    "Denial of Service",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"namespaces"},
		Verbs:       []string{"delete"},
		Tags:        []RiskTag{NamespaceLifecycle, ResourceDeletion, DenialOfService},
	},

	// --- RBAC API Group (rbac.authorization.k8s.io/v1) ---
	{
		Description: "Manage ClusterRoles (create, update, patch, delete)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"clusterroles"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{RBACManipulation, ClusterAdminAccess, PrivilegeEscalation},
	},
	{
		Description: "Manage ClusterRoleBindings (create, update, patch, delete)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"clusterrolebindings"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{RBACManipulation, ClusterAdminAccess, PrivilegeEscalation, BindingToPrivilegedRole},
	},
	{
		Description: "Manage Roles in a namespace (create, update, patch, delete)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		RoleType:    "Role", // Can also be ClusterRole granting this for a specific namespace
		Resources:   []string{"roles"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{RBACManipulation, PrivilegeEscalation},
	},
	{
		Description: "Manage RoleBindings in a namespace (create, update, patch, delete)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh, // Can be Critical if binding a powerful ClusterRole
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		RoleType:    "Role", // Can also be ClusterRole granting this for a specific namespace
		Resources:   []string{"rolebindings"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{RBACManipulation, PrivilegeEscalation, BindingToPrivilegedRole},
	},
	{
		Description: "Escalate privileges via ClusterRoles (escalate verb)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"clusterroles"}, // Could also be on "roles"
		Verbs:       []string{"escalate"},
		Tags:        []RiskTag{RBACManipulation, ClusterAdminAccess, PrivilegeEscalation},
	},
	{
		Description: "Bind ClusterRoles to identities (bind verb)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"clusterroles"}, // Could also be on "roles"
		Verbs:       []string{"bind"},
		Tags:        []RiskTag{RBACManipulation, ClusterAdminAccess, PrivilegeEscalation, BindingToPrivilegedRole},
	},

	// --- Workload Controllers (apps/v1, batch/v1) ---
	{
		Description: "Manage Deployments cluster-wide (potential for privileged pod execution)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"apps"},
		RoleType:    "ClusterRole",
		Resources:   []string{"deployments"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PrivilegeEscalation, Persistence, Tampering},
	},
	{
		Description: "Manage Deployments in a namespace (potential for privileged pod execution)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{"apps"},
		RoleType:    "Role",
		Resources:   []string{"deployments"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PotentialPrivilegeEscalation, Persistence, Tampering},
	},
	{
		Description: "Manage DaemonSets cluster-wide (runs on all nodes, high impact)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"apps"},
		RoleType:    "ClusterRole",
		Resources:   []string{"daemonsets"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PrivilegeEscalation, Persistence, NodeAccess, Tampering},
	},
	{
		Description: "Manage DaemonSets in a namespace (runs on nodes, high impact)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical, // Daemonsets are inherently powerful
		APIGroups:   []string{"apps"},
		RoleType:    "Role",
		Resources:   []string{"daemonsets"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PrivilegeEscalation, Persistence, NodeAccess, Tampering},
	},
	{
		Description: "Manage StatefulSets cluster-wide",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"apps"},
		RoleType:    "ClusterRole",
		Resources:   []string{"statefulsets"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PrivilegeEscalation, Persistence, Tampering},
	},
	{
		Description: "Manage StatefulSets in a namespace",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{"apps"},
		RoleType:    "Role",
		Resources:   []string{"statefulsets"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PotentialPrivilegeEscalation, Persistence, Tampering},
	},
	{
		Description: "Manage CronJobs cluster-wide (scheduled privileged execution, persistence)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"batch"},
		RoleType:    "ClusterRole",
		Resources:   []string{"cronjobs"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PrivilegeEscalation, Persistence, Tampering},
	},
	{
		Description: "Manage CronJobs in a namespace (scheduled privileged execution, persistence)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{"batch"},
		RoleType:    "Role",
		Resources:   []string{"cronjobs"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PotentialPrivilegeEscalation, Persistence, Tampering},
	},
	{
		Description: "Manage Jobs cluster-wide (one-off privileged execution)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"batch"},
		RoleType:    "ClusterRole",
		Resources:   []string{"jobs"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PrivilegeEscalation, Tampering},
	},
	{
		Description: "Manage Jobs in a namespace (one-off privileged execution)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{"batch"},
		RoleType:    "Role",
		Resources:   []string{"jobs"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WorkloadLifecycle, PotentialPrivilegeEscalation, Tampering},
	},

	// --- Admission Control (admissionregistration.k8s.io/v1) ---
	{
		Description: "Manage MutatingWebhookConfigurations",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"admissionregistration.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"mutatingwebhookconfigurations"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WebhookManipulation, Tampering, PrivilegeEscalation, DenialOfService},
	},
	{
		Description: "Manage ValidatingWebhookConfigurations",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"admissionregistration.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"validatingwebhookconfigurations"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{WebhookManipulation, Tampering, DenialOfService}, // Less direct EoP than mutating, but can still be abused.
	},

	// --- API Extensions (apiextensions.k8s.io/v1, apiregistration.k8s.io/v1) ---
	{
		Description: "Manage CustomResourceDefinitions",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"apiextensions.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"customresourcedefinitions"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{CRDManipulation, Tampering, PotentialPrivilegeEscalation},
	},
	{
		Description: "Manage APIServices",
		Category:    "Tampering",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"apiregistration.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"apiservices"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{APIServiceManipulation, Tampering, PrivilegeEscalation, DenialOfService, InformationDisclosure},
	},

	// --- Authentication & Authorization (authentication.k8s.io/v1, authorization.k8s.io/v1) ---
	{
		Description: "Create ServiceAccount Tokens",
		Category:    "Spoofing",
		RiskLevel:   RiskLevelCritical,                 // If SA is powerful or can be bound to powerful roles
		APIGroups:   []string{"authentication.k8s.io"}, // As per matrix entry for serviceaccounts/token
		RoleType:    "Role",                            // TokenRequest is namespaced for serviceaccounts
		Resources:   []string{"serviceaccounts/token"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{TokenCreation, Impersonation, CredentialAccess, PotentialPrivilegeEscalation, Spoofing},
	},
	{
		Description: "Create ServiceAccount Tokens (ClusterRole for any SA in any namespace)",
		Category:    "Spoofing",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"authentication.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"serviceaccounts/token"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{TokenCreation, Impersonation, CredentialAccess, PrivilegeEscalation, Spoofing},
	},
	{
		Description: "Create TokenReviews (validate arbitrary tokens)",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{"authentication.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"tokenreviews"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{InformationDisclosure, CredentialAccess, RBACQuery},
	},
	{
		Description: "Create SubjectAccessReviews (check arbitrary permissions)",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{"authorization.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"subjectaccessreviews"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{InformationDisclosure, RBACQuery},
	},
	{
		Description: "Create LocalSubjectAccessReviews (check permissions in a namespace)",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelLow,
		APIGroups:   []string{"authorization.k8s.io"},
		RoleType:    "Role",
		Resources:   []string{"localsubjectaccessreviews"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{InformationDisclosure, RBACQuery},
	},

	// --- Certificates (certificates.k8s.io/v1) ---
	{
		Description: "Approve CertificateSigningRequests",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"certificates.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"certificatesigningrequests/approval"},
		Verbs:       []string{"update", "patch"}, // "get" to view, "update/patch" to approve
		Tags:        []RiskTag{CSRApproval, PrivilegeEscalation, Spoofing, ClusterAdminAccess},
	},
	{
		Description: "Create CertificateSigningRequests",
		Category:    "Spoofing",
		RiskLevel:   RiskLevelMedium, // Risk depends on signer configuration
		APIGroups:   []string{"certificates.k8s.io"},
		RoleType:    "ClusterRole", // CSRs are cluster-scoped
		Resources:   []string{"certificatesigningrequests"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{CSRCreation, PotentialPrivilegeEscalation, Spoofing},
	},
	{
		Description: "Manage (get, list, watch, delete) CertificateSigningRequests",
		Category:    "Information Disclosure", // Or Tampering/DoS if delete
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{"certificates.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"certificatesigningrequests"},
		Verbs:       []string{"get", "list", "watch", "delete"},
		Tags:        []RiskTag{InformationDisclosure, Tampering, DenialOfService},
	},

	// --- Storage (storage.k8s.io/v1) ---
	{
		Description: "Manage CSIDrivers (potential node compromise)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"storage.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"csidrivers"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{StorageManipulation, Tampering, PrivilegeEscalation, NodeAccess},
	},
	{
		Description: "Manage StorageClasses",
		Category:    "Tampering",
		RiskLevel:   RiskLevelHigh,
		APIGroups:   []string{"storage.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"storageclasses"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{StorageManipulation, Tampering, DenialOfService},
	},

	// --- Policy (policy/v1) ---
	{
		Description: "Evict Pods cluster-wide",
		Category:    "Denial of Service",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{"policy"}, // As per matrix entry for pods/eviction
		RoleType:    "ClusterRole",
		Resources:   []string{"pods/eviction"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{DenialOfService, WorkloadLifecycle},
	},
	{
		Description: "Evict Pods in a namespace",
		Category:    "Denial of Service",
		RiskLevel:   RiskLevelMedium,
		APIGroups:   []string{"policy"},
		RoleType:    "Role",
		Resources:   []string{"pods/eviction"},
		Verbs:       []string{"create"},
		Tags:        []RiskTag{DenialOfService, WorkloadLifecycle},
	},

	// --- Node related (node.k8s.io/v1) ---
	{
		Description: "Manage RuntimeClasses",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"node.k8s.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"runtimeclasses"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{NodeAccess, Tampering, PrivilegeEscalation, PotentialPrivilegeEscalation},
	},

	// --- Wildcard Permissions ---
	{
		Description: "Wildcard permission on all resources cluster-wide (Cluster Admin)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"*"},
		RoleType:    "ClusterRole",
		Resources:   []string{"*"},
		Verbs:       []string{"*"},
		Tags:        []RiskTag{ClusterAdminAccess, PrivilegeEscalation, WildcardPermission, Tampering, InformationDisclosure, DenialOfService, Spoofing},
	},
	{
		Description: "Wildcard permission on all resources in a namespace (Namespace Admin)",
		Category:    "Elevation of Privilege",
		RiskLevel:   RiskLevelCritical, // Namespace admin can often escalate to cluster admin
		APIGroups:   []string{"*"},
		RoleType:    "Role",
		Resources:   []string{"*"},
		Verbs:       []string{"*"},
		Tags:        []RiskTag{NamespaceAdmin, PotentialPrivilegeEscalation, WildcardPermission, Tampering, InformationDisclosure, DenialOfService, Spoofing},
	},

	// --- Specific CRDs (Examples) ---
	{
		Description: "Manage ClusterIssuers (cert-manager.io)",
		Category:    "Spoofing",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"cert-manager.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"clusterissuers"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{CertificateManagement, Spoofing, Tampering, ElevationOfPrivilege},
	},
	{
		Description: "Manage ArgoCD Applications (argoproj.io)",
		Category:    "Tampering", // Can lead to EoP by deploying malicious workloads
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"argoproj.io"},
		RoleType:    "Role",                                                  // Typically namespaced, but impact can be cluster-wide
		Resources:   []string{"applications"},                                // Also applicationsets, appprojects
		Verbs:       []string{"create", "update", "patch", "delete", "sync"}, // sync is an argo verb often mapped
		Tags:        []RiskTag{WorkloadDeployment, Tampering, PotentialPrivilegeEscalation, CodeExecution},
	},
	{
		Description: "Manage Cilium ClusterwideNetworkPolicies (cilium.io)",
		Category:    "NetworkManipulation",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"cilium.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"ciliumclusterwidenetworkpolicies"},
		Verbs:       []string{"create", "update", "patch", "delete"},
		Tags:        []RiskTag{NetworkPolicyManagement, NetworkManipulation, Tampering, DenialOfService},
	},
	{
		Description: "Manage ETCDSnapshotFiles (k3s.cattle.io)",
		Category:    "Information Disclosure", // Access to full cluster state
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{"k3s.cattle.io"},
		RoleType:    "ClusterRole",
		Resources:   []string{"etcdsnapshotfiles"},
		Verbs:       []string{"get", "list", "create", "update", "delete"}, // All verbs are dangerous
		Tags:        []RiskTag{BackupAccess, ClusterAdminAccess, DataExposure, CredentialAccess, Tampering},
	},
}

// MatchRiskRule checks if a table row matches any of the defined risk rules
// and returns the matching rule or nil if no match is found
func MatchRiskRule(row SARoleBindingEntry) *RiskRule {
	// First, determine the base risk level based on role type and wildcards
	var baseRisk RiskLevel
	var description string
	var category string

	// Determine base risk based on role type and scope
	if row.RoleType == "ClusterRole" {
		// Only set Critical if we don't find a more specific rule
		if row.APIGroup == "*" && row.Resource == "*" && contains(row.Verbs, "*") {
			// Full cluster admin access
			baseRisk = RiskLevelCritical
			description = "Full cluster admin access"
			category = "Broad Cluster Access"
		} else if (row.APIGroup == "*" && row.Resource == "*") ||
			(row.Resource == "*" && contains(row.Verbs, "*")) {
			// Cluster-wide access but limited
			baseRisk = RiskLevelHigh
			description = "Cluster-wide access across all namespaces but limited"
			category = "API Group Wildcard Access"
		} else {
			// ClusterRole but limited resources/verbs
			baseRisk = RiskLevelMedium
			description = "Cluster-wide access with limited resources or verbs"
			category = "Limited Cluster Access"
		}
	} else { // Role (namespaced)
		if row.Resource == "*" && contains(row.Verbs, "*") {
			// Full access within namespace
			baseRisk = RiskLevelMedium
			description = "Full access within namespace"
			category = "Broad Namespace Access"
		} else {
			// Limited access within namespace
			baseRisk = RiskLevelLow
			description = "Limited access within namespace"
			category = "Limited Namespace Access"
		}
	}

	// Create base rule with initial risk assessment
	resultRule := &RiskRule{
		Description: description,
		Category:    category,
		RiskLevel:   baseRisk,
		RoleType:    row.RoleType,
		APIGroups:   []string{row.APIGroup},
		Resources:   []string{row.Resource},
		Verbs:       row.Verbs,
	}

	// Sort rules by specificity (most specific first) and risk level
	sortedRules := make([]RiskRule, len(RiskRules))
	copy(sortedRules, RiskRules)
	sort.Slice(sortedRules, func(i, j int) bool {
		ruleI := sortedRules[i]
		ruleJ := sortedRules[j]

		// If risk levels are different, higher risk comes first
		if ruleI.RiskLevel != ruleJ.RiskLevel {
			return ruleI.RiskLevel > ruleJ.RiskLevel
		}

		// Calculate rule specificity scores
		iSpecificity := 0
		if contains(ruleI.APIGroups, "*") {
			iSpecificity++
		}
		if contains(ruleI.Resources, "*") {
			iSpecificity++
		}
		if contains(ruleI.Verbs, "*") {
			iSpecificity++
		}

		jSpecificity := 0
		if contains(ruleJ.APIGroups, "*") {
			jSpecificity++
		}
		if contains(ruleJ.Resources, "*") {
			jSpecificity++
		}
		if contains(ruleJ.Verbs, "*") {
			jSpecificity++
		}

		// For equal risk levels, if one rule is all wildcards and input has all wildcards,
		// prefer that rule over more specific ones
		if row.APIGroup == "*" && row.Resource == "*" && contains(row.Verbs, "*") {
			// If both rules are all wildcards or neither is, maintain normal specificity order
			if (iSpecificity == 3 && jSpecificity == 3) || (iSpecificity < 3 && jSpecificity < 3) {
				return iSpecificity < jSpecificity
			}
			// Otherwise prefer the all-wildcard rule
			return iSpecificity > jSpecificity
		}

		// Default to preferring more specific rules
		return iSpecificity < jSpecificity
	})

	// Now check for specific rules that might increase the risk level
	for _, rule := range sortedRules {
		// Skip rules that don't match the role type
		if rule.RoleType != row.RoleType {
			continue
		}

		// Check if the rule matches
		matches := true

		// Skip if rule has a lower risk level than our current base risk
		// Allow equal risk level if the current result is from base assessment
		if rule.RiskLevel < resultRule.RiskLevel ||
			(rule.RiskLevel == resultRule.RiskLevel && resultRule.Tags != nil) {
			continue
		}

		// For wildcard rules, check if the input matches exactly
		if contains(rule.APIGroups, "*") && contains(rule.Resources, "*") && contains(rule.Verbs, "*") {
			// For full admin rule, require exact match
			if row.APIGroup != "*" || row.Resource != "*" || !contains(row.Verbs, "*") {
				matches = false
			}
		} else {
			// API Groups: match if either has wildcard or exact match
			if row.APIGroup != "*" && !contains(rule.APIGroups, "*") {
				apiGroupMatched := false
				// Special handling for core API group (empty string)
				if len(rule.APIGroups) == 0 && row.APIGroup == "" {
					apiGroupMatched = true
				} else {
					for _, ruleGroup := range rule.APIGroups {
						if ruleGroup == row.APIGroup {
							apiGroupMatched = true
							break
						}
					}
				}
				if !apiGroupMatched {
					matches = false
				}
			}

			// Resources: match if either has wildcard or exact match
			if row.Resource != "*" && !contains(rule.Resources, "*") && !contains(rule.Resources, row.Resource) {
				matches = false
			}

			// Verbs: match if either has wildcard or all required verbs are present
			if !contains(row.Verbs, "*") && !contains(rule.Verbs, "*") {
				for _, requiredVerb := range rule.Verbs {
					if !contains(row.Verbs, requiredVerb) {
						matches = false
						break
					}
				}
			}
		}

		// If rule matches and has higher or equal risk (from base), upgrade the risk level and details
		if matches && (rule.RiskLevel >= resultRule.RiskLevel && resultRule.Tags == nil) {
			// Create a new copy of the rule to avoid reference issues
			newRule := rule
			resultRule = &newRule
		}
	}

	return resultRule
}
