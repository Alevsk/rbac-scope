package policyevaluation

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMatchRiskRules(t *testing.T) {
	tests := []struct {
		name             string
		policy           Policy
		wantErr          bool
		wantRiskLevel    RiskLevel
		wantMatchesCount int
	}{
		{
			name: "Cluster-wide pod exec",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Namespaced pod exec",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "",
				Resource:  "pods/exec",
				Verbs:     []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Cluster-wide pod attach",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/attach",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Namespaced pod attach",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/attach",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Cluster-wide pod port-forward",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/portforward",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Namespaced pod port-forward",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/portforward",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Create pods cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Create pods in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Update/Patch pods cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Update/Patch pods in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Read secrets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Read secrets in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Modify secrets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Modify secrets in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Node proxy access (Kubelet API)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/proxy",
				Verbs:    []string{"get", "create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Modify node configuration (labels, taints)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"patch", "update"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Delete nodes",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"delete", "deletecollection"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage PersistentVolumes (cluster-wide storage manipulation)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "persistentvolumes",
				Verbs:    []string{"create", "update", "patch", "delete", "deletecollection"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Read pod logs cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/log",
				Verbs:    []string{"get"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Read pod logs in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/log",
				Verbs:    []string{"get"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ephemeral containers cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/ephemeralcontainers",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ephemeral containers in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/ephemeralcontainers",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Read ConfigMaps cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Read ConfigMaps in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Modify ConfigMaps cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Modify ConfigMaps in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Delete namespaces",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []string{"delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ClusterRoles (create, update, patch, delete)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ClusterRoleBindings (create, update, patch, delete)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterrolebindings",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Roles in a namespace (create, update, patch, delete)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "roles",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage RoleBindings in a namespace (create, update, patch, delete)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "rolebindings",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Escalate privileges via ClusterRoles (escalate verb)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"escalate"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Bind ClusterRoles to identities (bind verb)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"bind"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Deployments cluster-wide (potential for privileged pod execution)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Deployments in a namespace (potential for privileged pod execution)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage DaemonSets cluster-wide (runs on all nodes, high impact)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "daemonsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage DaemonSets in a namespace (runs on nodes, high impact)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "daemonsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage StatefulSets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "statefulsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage StatefulSets in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "statefulsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage CronJobs cluster-wide (scheduled privileged execution, persistence)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "batch",
				Resource: "cronjobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage CronJobs in a namespace (scheduled privileged execution, persistence)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "batch",
				Resource: "cronjobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Jobs cluster-wide (one-off privileged execution)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "batch",
				Resource: "jobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Jobs in a namespace (one-off privileged execution)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "batch",
				Resource: "jobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage MutatingWebhookConfigurations",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "mutatingwebhookconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ValidatingWebhookConfigurations",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "validatingwebhookconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage CustomResourceDefinitions",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apiextensions.k8s.io",
				Resource: "customresourcedefinitions",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage APIServices",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apiregistration.k8s.io",
				Resource: "apiservices",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Create ServiceAccount Tokens",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "authentication.k8s.io",
				Resource: "serviceaccounts/token",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Create ServiceAccount Tokens (ClusterRole for any SA in any namespace)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authentication.k8s.io",
				Resource: "serviceaccounts/token",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Create TokenReviews (validate arbitrary tokens)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authentication.k8s.io",
				Resource: "tokenreviews",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Create SubjectAccessReviews (check arbitrary permissions)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authorization.k8s.io",
				Resource: "subjectaccessreviews",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Create LocalSubjectAccessReviews (check permissions in a namespace)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "authorization.k8s.io",
				Resource: "localsubjectaccessreviews",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelLow,
			wantMatchesCount: 2,
		},
		{
			name: "Approve CertificateSigningRequests",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests/approval",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Create CertificateSigningRequests",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Manage (get, list, watch, delete) CertificateSigningRequests",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests",
				Verbs:    []string{"get", "list", "watch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Manage CSIDrivers (potential node compromise)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "csidrivers",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage StorageClasses",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "storageclasses",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Evict Pods cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "pods/eviction",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Evict Pods in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "policy",
				Resource: "pods/eviction",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Manage RuntimeClasses",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "node.k8s.io",
				Resource: "runtimeclasses",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Wildcard permission on all resources cluster-wide (Cluster Admin)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Wildcard permission on all resources in a namespace (Namespace Admin)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ClusterIssuers (cert-manager.io)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "cert-manager.io",
				Resource: "clusterissuers",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ArgoCD Applications (argoproj.io)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "argoproj.io",
				Resource: "applications",
				Verbs:    []string{"create", "update", "patch", "delete", "sync"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Cilium ClusterwideNetworkPolicies (cilium.io)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "cilium.io",
				Resource: "ciliumclusterwidenetworkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ETCDSnapshotFiles (k3s.cattle.io)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "k3s.cattle.io",
				Resource: "etcdsnapshotfiles",
				Verbs:    []string{"get", "list", "create", "update", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Impersonate users cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "users",
				Verbs:    []string{"impersonate"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2, // Assuming this specific policy matches one defined rule
		},
		{
			name: "Impersonate groups cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "groups",
				Verbs:    []string{"impersonate"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Impersonate serviceaccounts cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"impersonate"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Impersonate userextras cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "userextras",
				Verbs:    []string{"impersonate"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Impersonate uids cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "uids",
				Verbs:    []string{"impersonate"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ServiceAccounts cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage ServiceAccounts in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Patch node status cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/status",
				Verbs:    []string{"patch", "update"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Read events cluster-wide (core API group)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "", // Core API group for events
				Resource: "events",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Read events cluster-wide (events.k8s.io API group)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "events.k8s.io", // events.k8s.io API group
				Resource: "events",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Manage NetworkPolicies cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage NetworkPolicies in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Endpoints cluster-wide (core API)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "", // Core API group for Endpoints
				Resource: "endpoints",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage EndpointSlices cluster-wide (discovery.k8s.io API)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "discovery.k8s.io", // discovery.k8s.io for EndpointSlices
				Resource: "endpointslices",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Endpoints in a namespace (core API)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "", // Core API group for Endpoints
				Resource: "endpoints",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage EndpointSlices in a namespace (discovery.k8s.io API)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "discovery.k8s.io", // discovery.k8s.io for EndpointSlices
				Resource: "endpointslices",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Services cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "services",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Services in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "services",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Read RBAC ClusterRoles cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Read RBAC Roles cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "roles",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Read RBAC ClusterRoleBindings cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterrolebindings",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Read RBAC RoleBindings cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "rolebindings",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Use privileged PodSecurityPolicy (policy API group)",
			policy: Policy{
				RoleType: "ClusterRole", // Or Role, depending on binding context
				APIGroup: "policy",
				Resource: "podsecuritypolicies",
				Verbs:    []string{"use"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical, // Risk depends on specific PSP, but "use" is key
			wantMatchesCount: 2,
		},
		{
			name: "Use privileged PodSecurityPolicy (extensions API group)",
			policy: Policy{
				RoleType: "ClusterRole", // Or Role
				APIGroup: "extensions",  // Older API group for PSPs
				Resource: "podsecuritypolicies",
				Verbs:    []string{"use"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Manage PodDisruptionBudgets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "poddisruptionbudgets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelMedium,
			wantMatchesCount: 2,
		},
		{
			name: "Manage Leases cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "coordination.k8s.io",
				Resource: "leases",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		// {
		// 	// TODO: implement resourceNames: ["kube-system", "kube-node-lease"]
		// 	name: "Manage Leases in critical namespace (Role)",
		// 	// This test case assumes the scanner can identify the namespace from RoleBinding context.
		// 	// The Policy struct here only defines the RBAC rule part.
		// 	// The RiskLevelCritical is for the *combination* of this rule in a critical namespace.
		// 	policy: Policy{
		// 		RoleType: "Role",
		// 		APIGroup: "coordination.k8s.io",
		// 		Resource: "leases",
		// 		Verbs:    []string{"create", "update", "patch", "delete"},
		// 	},
		// 	wantErr:          false,
		// 	wantRiskLevel:    RiskLevelCritical, // Risk is high if this Role is bound in kube-system etc.
		// 	wantMatchesCount: 2,
		// },
		{
			name: "List Namespaces (Cluster Reconnaissance)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []string{"list", "watch"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelLow,
			wantMatchesCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchRiskRules(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchRiskRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if len(got) != tt.wantMatchesCount {
				t.Errorf("MatchRiskRules() returned %d matches, want %d", len(got), tt.wantMatchesCount)
				return
			}

			// Check if we got the expected risk level
			highestRiskLevel := got[0].RiskLevel
			if highestRiskLevel != tt.wantRiskLevel {
				t.Errorf("MatchRiskRules() highest risk level = %v, want %v", highestRiskLevel, tt.wantRiskLevel)
			}
		})
	}
}

func TestContainsWildcard(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"Exact wildcard", "*", true},
		{"Contains wildcard", "deploy*", true},
		{"No wildcard", "deployments", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsWildcard(tt.s); got != tt.want {
				t.Errorf("containsWildcard() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainsWildcardInSlice(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  bool
	}{
		{
			name:  "Contains wildcard",
			items: []string{"get", "*", "list"},
			want:  true,
		},
		{
			name:  "No wildcard",
			items: []string{"get", "list", "watch"},
			want:  false,
		},
		{
			name:  "Empty slice",
			items: []string{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsWildcardInSlice(tt.items); got != tt.want {
				t.Errorf("containsWildcardInSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

type K8sRoleRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

type K8sRole struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Rules []K8sRoleRule `yaml:"rules"`
}

func TestEvaluateFixtures(t *testing.T) {
	tests := []struct {
		name             string
		fixture          string
		wantRiskLevel    RiskLevel
		wantMatchesCount int
	}{
		{
			name:             "Secrets reader cluster role",
			fixture:          "testdata/fixtures/secrets-reader.yaml",
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name:             "Cluster admin access",
			fixture:          "testdata/fixtures/cluster-admin-access.yaml",
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load fixture
			data, err := os.ReadFile(tt.fixture)
			if err != nil {
				t.Fatalf("Failed to read fixture: %v", err)
			}

			// Parse YAML
			var role K8sRole
			if err := yaml.Unmarshal(data, &role); err != nil {
				t.Fatalf("Failed to unmarshal YAML: %v", err)
			}

			// Convert K8s role to our Policy type
			policy := Policy{
				RoleType:  role.Kind,
				RoleName:  role.Metadata.Name,
				Namespace: "", // ClusterRole has no namespace
			}

			// Process the first rule (assuming single rule for simplicity)
			if len(role.Rules) > 0 {
				rule := role.Rules[0]

				// For cluster-admin-like access, if any value is "*", use that
				policy.APIGroup = ""
				for _, apiGroup := range rule.APIGroups {
					if apiGroup == "*" {
						policy.APIGroup = "*"
						break
					}
					if policy.APIGroup == "" {
						policy.APIGroup = apiGroup
					}
				}

				policy.Resource = ""
				for _, resource := range rule.Resources {
					if resource == "*" {
						policy.Resource = "*"
						break
					}
					if policy.Resource == "" {
						policy.Resource = resource
					}
				}

				policy.Verbs = rule.Verbs
			}

			// Get matches
			matches, err := MatchRiskRules(policy)
			if err != nil {
				t.Fatalf("MatchRiskRules() error = %v", err)
			}

			// Check number of matches
			if len(matches) != tt.wantMatchesCount {
				t.Errorf("MatchRiskRules() returned %d matches, want %d", len(matches), tt.wantMatchesCount)
				return
			}

			// Check highest risk level
			highestRiskLevel := matches[0].RiskLevel
			if highestRiskLevel != tt.wantRiskLevel {
				t.Errorf("MatchRiskRules() highest risk level = %v, want %v", highestRiskLevel, tt.wantRiskLevel)
			}
		})
	}
}
