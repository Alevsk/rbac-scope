package policyevaluation

import (
	"os"
	"sort"
	"testing"

	"github.com/alevsk/rbac-ops/internal/config"
	"github.com/alevsk/rbac-ops/internal/logger"
	"gopkg.in/yaml.v3"
)

func TestMatchRiskRules(t *testing.T) {
	// suppress debug logging
	cfg := &config.Config{
		Debug: false,
	}
	logger.Init(cfg)

	// Helper function to compare slices of RiskRule
	compareRiskRules := func(got []RiskRule, want []int64) bool {
		if len(got) != len(want) {
			return false
		}
		// Sort both slices by ID to ensure consistent comparison
		sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })

		for i := range got {
			if got[i].ID != want[i] {
				return false
			}
		}
		return true
	}

	type matchRiskRulesTest struct {
		name          string
		policy        Policy
		wantErr       bool
		wantRiskLevel RiskLevel
		testType      string  // "exact", "count"
		wantRulesIDs  []int64 // for exact match validation
		wantCount     int     // for count validation or minimal validation
	}

	tests := []matchRiskRulesTest{
		{
			name: "Critical: Wildcard permission on all resources cluster-wide (Cluster Admin)", // Corrected name to match YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "count",
			wantCount:     105,
		},
		{
			name: "Cluster-wide pod exec", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"create"}, // Added verbs from YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "count",
			wantCount:     3, // Assuming this matches one specific rule
		},
		{
			name: "Namespaced pod exec", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/exec",
				Verbs:     []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Cluster-wide pod attach", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/attach",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Namespaced pod attach", // NEW: Added missing test case
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/attach",
				Verbs:     []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Cluster-wide pod exec with wildcard verbs", // Behavioral test, not direct YAML rule
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"*"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Consistent with the spirit of pods/exec
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Cluster-wide pod port-forward", // NEW: Added missing test case
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/portforward",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Namespaced pod port-forward", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/portforward",
				Verbs:     []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create pods cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Create pods in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods",
				Verbs:     []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update/Patch pods cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Update/Patch pods in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods",
				Verbs:     []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read secrets cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Read secrets in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "secrets",
				Verbs:     []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from Medium to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Modify secrets cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Modify secrets in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "secrets",
				Verbs:     []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from Medium to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Node proxy access (Kubelet API)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/proxy",
				Verbs:    []string{"get", "create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Modify node configuration (labels, taints)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"patch", "update"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Delete nodes", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"delete", "deletecollection"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage PersistentVolumes (cluster-wide storage manipulation)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "persistentvolumes",
				Verbs:    []string{"create", "update", "patch", "delete", "deletecollection"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read pod logs cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/log",
				Verbs:    []string{"get"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Read pod logs in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/log",
				Verbs:     []string{"get"}, // Corrected verbs to match YAML exactly
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage ephemeral containers cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/ephemeralcontainers",
				Verbs:    []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Manage ephemeral containers in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/ephemeralcontainers",
				Verbs:     []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read ConfigMaps cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Read ConfigMaps in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "configmaps",
				Verbs:     []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Modify ConfigMaps cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Modify ConfigMaps in a namespace", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "configmaps",
				Verbs:     []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Delete namespaces", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []string{"delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage ClusterRoles (create, update, patch, delete)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1027, 0},
			wantCount:     2,
		},
		{
			name: "Manage ClusterRoleBindings (create, update, patch, delete)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterrolebindings",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1028, 0},
			wantCount:     2,
		},
		{
			name: "Manage Roles in a namespace (create, update, patch, delete)", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "rbac.authorization.k8s.io",
				Resource:  "roles",
				Verbs:     []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage RoleBindings in a namespace (create, update, patch, delete)", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "rbac.authorization.k8s.io",
				Resource:  "rolebindings",
				Verbs:     []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Escalate privileges via ClusterRoles (escalate verb)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"escalate"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1031, 0},
			wantCount:     2,
		},
		{
			name: "Bind ClusterRoles to identities (bind verb)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"bind"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1032, 0},
			wantCount:     2,
		},
		{
			name: "Manage Deployments cluster-wide (potential for privileged pod execution)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1033, 1034, 0},
			wantCount:     3,
		},
		{
			name: "Manage Deployments in a namespace (potential for privileged pod execution)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage DaemonSets cluster-wide (runs on all nodes, high impact)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "daemonsets",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1035, 1036, 0},
			wantCount:     3,
		},
		{
			name: "Manage DaemonSets in a namespace (runs on nodes, high impact)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "daemonsets",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1036, 0},
			wantCount:     2,
		},
		{
			name: "Manage StatefulSets cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "statefulsets",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1037, 1038, 0},
			wantCount:     3,
		},
		{
			name: "Manage StatefulSets in a namespace", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "statefulsets",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage CronJobs cluster-wide (scheduled privileged execution, persistence)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "batch",
				Resource: "cronjobs",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1039, 1040, 0},
			wantCount:     3,
		},
		{
			name: "Manage CronJobs in a namespace (scheduled privileged execution, persistence)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "batch",
				Resource: "cronjobs",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Jobs cluster-wide (one-off privileged execution)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "batch",
				Resource: "jobs",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1041, 1042, 0},
			wantCount:     3,
		},
		{
			name: "Manage Jobs in a namespace (one-off privileged execution)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "batch",
				Resource: "jobs",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage MutatingWebhookConfigurations", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "mutatingwebhookconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1043, 0},
			wantCount:     2,
		},
		{
			name: "Manage ValidatingWebhookConfigurations", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "validatingwebhookconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1044, 0},
			wantCount:     2,
		},
		{
			name: "Manage CustomResourceDefinitions", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apiextensions.k8s.io",
				Resource: "customresourcedefinitions",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1045, 0},
			wantCount:     2,
		},
		{
			name: "Manage APIServices", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apiregistration.k8s.io",
				Resource: "apiservices",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1046, 0},
			wantCount:     2,
		},
		{
			name: "Create ServiceAccount Tokens", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "authentication.k8s.io",
				Resource: "serviceaccounts/token",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1047, 0},
			wantCount:     2,
		},
		{
			name: "Create ServiceAccount Tokens (ClusterRole for any SA in any namespace)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authentication.k8s.io",
				Resource: "serviceaccounts/token",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1047, 1048, 0},
			wantCount:     3,
		},
		{
			name: "Create TokenReviews (validate arbitrary tokens)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authentication.k8s.io",
				Resource: "tokenreviews",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create SubjectAccessReviews (check arbitrary permissions)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authorization.k8s.io",
				Resource: "subjectaccessreviews",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create LocalSubjectAccessReviews (check permissions in a namespace)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "authorization.k8s.io",
				Resource: "localsubjectaccessreviews",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Approve CertificateSigningRequests", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests/approval",
				Verbs:    []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1052, 0},
			wantCount:     2,
		},
		{
			name: "Create CertificateSigningRequests", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage (get, list, watch, delete) CertificateSigningRequests", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests",
				Verbs:    []string{"get", "list", "watch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage CSIDrivers (potential node compromise)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "csidrivers",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1055, 0},
			wantCount:     2,
		},
		{
			name: "Manage StorageClasses", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "storageclasses",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Evict Pods cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "pods/eviction",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Evict Pods in a namespace", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "policy",
				Resource: "pods/eviction",
				Verbs:    []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage RuntimeClasses", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "node.k8s.io",
				Resource: "runtimeclasses",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1059, 0},
			wantCount:     2,
		},
		{
			name: "Wildcard permission on all resources cluster-wide (Cluster Admin)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs: []int64{
				1039,
				1047, 1002, 1075, 1073, 1071, 1006, 1078, 1008, 1080, 1010, 1011, 1036, 1013, 1014, 1015, 1016, 1017, 1066, 1102, 1020, 1065, 1064, 1099, 1024, 1063, 1062, 1027, 1028, 1061, 1060, 1031, 1032, 1033, 1059, 1035, 1012, 1081, 1052, 1055, 1092, 1041, 1000, 1043, 1044, 1045, 1046, 1037, 1048, 1098, 1004, 1072, 1038, 1042, 1040, 1076, 1056, 1091, 1001, 1034, 1025, 1097, 1096, 1029, 1009, 1021, 1018, 1067, 1022, 1069, 1007, 1103, 1030, 1026, 1074, 1003, 1053, 1089, 1070, 1079, 1068, 1058, 1005, 1083, 1084, 1085, 1019, 1100, 1023, 1077, 1090, 1057, 1054, 1093, 1094, 1095, 1049, 1050, 1051, 1088, 1087, 1101, 1086, 1082, 0,
			},
			wantCount: 105,
		},
		{
			name: "Wildcard permission on all resources in a namespace (Namespace Admin)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs: []int64{
				1081, 1036, 1063, 1061, 1047, 1011, 1013, 1034, 1040, 1096, 1025, 1029, 1030, 1076, 1097, 1038, 1021, 1042, 1003, 1091, 1009, 1007, 1103, 1001, 1072, 1074, 1085, 1068, 1023, 1094, 1058, 1019, 1005, 1086, 1087, 1088, 1051, 1101, 0,
			},
			wantCount: 39,
		},
		{
			name: "Manage ClusterIssuers (cert-manager.io)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "cert-manager.io",
				Resource: "clusterissuers",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1062, 0},
			wantCount:     2,
		},
		{
			name: "Manage ArgoCD Applications (argoproj.io)", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "argoproj.io",
				Resource: "applications",
				Verbs:    []string{"create", "update", "patch", "delete", "sync"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1063, 0},
			wantCount:     2,
		},
		{
			name: "Manage Cilium ClusterwideNetworkPolicies (cilium.io)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "cilium.io",
				Resource: "ciliumclusterwidenetworkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1064, 0},
			wantCount:     2,
		},
		{
			name: "Manage ETCDSnapshotFiles (k3s.cattle.io)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "k3s.cattle.io",
				Resource: "etcdsnapshotfiles",
				Verbs:    []string{"get", "list", "create", "update", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1065, 0},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - users", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "users",
				Verbs:    []string{"impersonate"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 0},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - groups", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "groups",
				Verbs:    []string{"impersonate"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 0},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - serviceaccounts", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"impersonate"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 0},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - userextras", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "userextras",
				Verbs:    []string{"impersonate"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 0},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - uids", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "uids",
				Verbs:    []string{"impersonate"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 0},
			wantCount:     2,
		},
		{
			name: "Manage ServiceAccounts cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Manage ServiceAccounts in a namespace", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Patch node status cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/status",
				Verbs:    []string{"patch", "update"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read events cluster-wide (core API group)", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "", // Core API group for events
				Resource: "events",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read events cluster-wide (events.k8s.io API group)", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "events.k8s.io", // events.k8s.io API group
				Resource: "events",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage NetworkPolicies cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1071, 1072, 0},
			wantCount:     3,
		},
		{
			name: "Manage NetworkPolicies in a namespace", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Endpoints or EndpointSlices cluster-wide (core API)", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "", // Core API group for Endpoints
				Resource: "endpoints",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1073, 1074, 0},
			wantCount:     3,
		},
		{
			name: "Manage Endpoints or EndpointSlices cluster-wide (discovery.k8s.io API)", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "discovery.k8s.io", // discovery.k8s.io for EndpointSlices
				Resource: "endpointslices",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1073, 1074, 0},
			wantCount:     3,
		},
		{
			name: "Manage Endpoints or EndpointSlices in a namespace (core API)", // Matches YAML (split test)
			policy: Policy{
				RoleType: "Role",
				APIGroup: "", // Core API group for Endpoints
				Resource: "endpoints",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Endpoints or EndpointSlices in a namespace (discovery.k8s.io API)", // Matches YAML (split test)
			policy: Policy{
				RoleType: "Role",
				APIGroup: "discovery.k8s.io", // discovery.k8s.io for EndpointSlices
				Resource: "endpointslices",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Services cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "services",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1075, 1076, 0},
			wantCount:     3,
		},
		{
			name: "Manage Services in a namespace", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "services",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - ClusterRoles", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - Roles", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "roles",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - ClusterRoleBindings", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterrolebindings",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - RoleBindings", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "rolebindings",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Use privileged PodSecurityPolicy (deprecated) - policy API group", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "podsecuritypolicies",
				Verbs:    []string{"use"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Use privileged PodSecurityPolicy (deprecated) - extensions API group", // Matches YAML (split test)
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "extensions", // Older API group for PSPs
				Resource: "podsecuritypolicies",
				Verbs:    []string{"use"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1078, 0},
			wantCount:     2,
		},
		{
			name: "Manage PodDisruptionBudgets cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "poddisruptionbudgets",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Leases cluster-wide", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "coordination.k8s.io",
				Resource: "leases",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1080, 1081, 0},
			wantCount:     3,
		},
		{
			// Note: The YAML rule "Manage Leases in kube-system or kube-node-lease namespace"
			// implies a Critical risk specifically when bound in those namespaces.
			// This test case uses Namespace: "default". The risk level is correct
			// if your scanner logic elevates risk based on the *binding* namespace.
			name: "Manage Leases in kube-system or kube-node-lease namespace", // Matches YAML
			policy: Policy{
				RoleType: "Role",
				APIGroup: "coordination.k8s.io",
				Resource: "leases",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "List Namespaces (Cluster Reconnaissance)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []string{"list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "List ValidatingWebhookConfigurations (Reconnaissance)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "validatingwebhookconfigurations",
				Verbs:    []string{"list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "List MutatingWebhookConfigurations (Reconnaissance)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "mutatingwebhookconfigurations",
				Verbs:    []string{"list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create/Update ControllerRevisions (Potential Tampering)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "controllerrevisions",
				Verbs:     []string{"create", "update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create SelfSubjectRulesReviews (Discover Own Permissions)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "authorization.k8s.io",
				Resource:  "selfsubjectrulesreviews",
				Verbs:     []string{"create"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read LimitRanges (Namespace Information Disclosure)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "",
				Resource:  "limitranges",
				Verbs:     []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read ResourceQuotas (Namespace Information Disclosure)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "",
				Resource:  "resourcequotas",
				Verbs:     []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read All ResourceQuotas (Cluster-wide Information Disclosure)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "resourcequotas",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Update CertificateSigningRequest Status (Tampering/DoS)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests/status",
				Verbs:    []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Ingresses (Namespace Service Exposure/Traffic Redirection)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "networking.k8s.io",
				Resource:  "ingresses",
				Verbs:     []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage IngressClasses (Cluster-wide Traffic Control Tampering)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "ingressclasses",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1092, 0},
			wantCount:     2,
		},
		{
			name: "Update NetworkPolicy Status (Cluster-wide Tampering)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies/status",
				Verbs:    []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update PodDisruptionBudget Status (Namespace Tampering/DoS)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "policy",
				Resource:  "poddisruptionbudgets/status",
				Verbs:     []string{"create", "update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read ComponentStatuses (Control Plane Reconnaissance)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "componentstatuses",
				Verbs:    []string{"get", "list"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update Deployment Scale (Resource Abuse/DoS)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "deployments/scale",
				Verbs:     []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update StatefulSet Scale (Resource Abuse/DoS)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "statefulsets/scale",
				Verbs:     []string{"update", "patch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage FlowSchemas (API Server DoS/Manipulation)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "flowcontrol.apiserver.k8s.io",
				Resource: "flowschemas",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1098, 0},
			wantCount:     2,
		},
		{
			name: "Manage PriorityLevelConfigurations (API Server DoS/Manipulation)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "flowcontrol.apiserver.k8s.io",
				Resource: "prioritylevelconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1099, 0},
			wantCount:     2,
		},
		{
			name: "Read CSINode Objects (Node & Storage Reconnaissance)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "csinodes",
				Verbs:    []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read CSIStorageCapacities (Namespace Storage Reconnaissance)", // Matches YAML
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "storage.k8s.io",
				Resource:  "csistoragecapacities",
				Verbs:     []string{"get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Matches YAML
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage VolumeAttachments (Cluster-wide Storage/Node Manipulation)", // Matches YAML
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "volumeattachments",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list", "watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1102, 0},
			wantCount:     2,
		},
		{
			name: "Watch All Resources in a Namespace (Broad Information Disclosure)", // Matches YAML
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "*",
				Resource:  "*",
				Verbs:     []string{"watch"}, // Matches YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Matches YAML
			testType:      "exact",
			wantRulesIDs:  []int64{1103, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchRiskRules(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchRiskRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check the highest risk level matches expected
			if len(got) > 0 && got[0].RiskLevel != tt.wantRiskLevel {
				t.Errorf("MatchRiskRules() highest risk level = %v, want %v", got[0].RiskLevel, tt.wantRiskLevel)
			}

			// Handle different test types
			switch tt.testType {
			case "exact":
				if !compareRiskRules(got, tt.wantRulesIDs) {
					ruleIds := []int64{}
					for _, rule := range got {
						ruleIds = append(ruleIds, rule.ID)
					}
					t.Errorf("MatchRiskRules() got = %v, want %v", ruleIds, tt.wantRulesIDs)
				}
			case "count":
				if len(got) != tt.wantCount {
					t.Errorf("MatchRiskRules() got %v rules, want %v", len(got), tt.wantCount)
				}
			default:
				t.Errorf("Invalid test type: %v", tt.testType)
			}
		})
	}
}

func TestIsClusterScoped(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   bool
	}{
		{
			name:   "ClusterRole type",
			policy: Policy{RoleType: "ClusterRole", Namespace: "default"},
			want:   true,
		},
		{
			name:   "Empty namespace",
			policy: Policy{RoleType: "Role", Namespace: ""},
			want:   true,
		},
		{
			name:   "Role type with namespace",
			policy: Policy{RoleType: "Role", Namespace: "default"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isClusterScoped(&tt.policy); got != tt.want {
				t.Errorf("isClusterScoped() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineBaseRiskLevel(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   RiskLevel
	}{
		{
			name:   "Critical - ClusterRole, all wildcards",
			policy: Policy{RoleType: "ClusterRole", APIGroup: "*", Resource: "*", Verbs: []string{"*"}},
			want:   RiskLevelCritical,
		},
		{
			name:   "High - ClusterRole, APIGroup wildcard",
			policy: Policy{RoleType: "ClusterRole", APIGroup: "*", Resource: "pods", Verbs: []string{"get"}},
			want:   RiskLevelHigh,
		},
		{
			name:   "High - ClusterRole, Resource wildcard",
			policy: Policy{RoleType: "ClusterRole", APIGroup: "", Resource: "*", Verbs: []string{"get"}},
			want:   RiskLevelHigh,
		},
		{
			name:   "High - ClusterRole, Verbs wildcard",
			policy: Policy{RoleType: "ClusterRole", APIGroup: "", Resource: "pods", Verbs: []string{"*"}},
			want:   RiskLevelHigh,
		},
		{
			name:   "Medium - Namespaced Role, APIGroup wildcard",
			policy: Policy{RoleType: "Role", Namespace: "default", APIGroup: "*", Resource: "pods", Verbs: []string{"get"}},
			want:   RiskLevelMedium,
		},
		{
			name:   "Medium - Namespaced Role, Resource wildcard",
			policy: Policy{RoleType: "Role", Namespace: "default", APIGroup: "", Resource: "*", Verbs: []string{"get"}},
			want:   RiskLevelMedium,
		},
		{
			name:   "Medium - Namespaced Role, Verbs wildcard",
			policy: Policy{RoleType: "Role", Namespace: "default", APIGroup: "", Resource: "pods", Verbs: []string{"*"}},
			want:   RiskLevelMedium,
		},
		{
			name:   "Low - Namespaced Role, no wildcards",
			policy: Policy{RoleType: "Role", Namespace: "default", APIGroup: "", Resource: "pods", Verbs: []string{"get"}},
			want:   RiskLevelLow,
		},
		{
			name:   "Low - ClusterRole, no wildcards (should default to Low as per logic if not Critical/High)",
			policy: Policy{RoleType: "ClusterRole", APIGroup: "apps", Resource: "deployments", Verbs: []string{"list"}},
			want:   RiskLevelLow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := determineBaseRiskLevel(&tt.policy); got != tt.want {
				t.Errorf("determineBaseRiskLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesAPIGroups(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		rule   RiskRule
		want   bool
	}{
		// Rule has wildcard
		{
			name:   "Rule wildcard, policy wildcard",
			policy: Policy{APIGroup: "*"},
			rule:   RiskRule{APIGroups: []string{"*"}},
			want:   true,
		},
		{
			name:   "Rule wildcard, policy specific (fail)",
			policy: Policy{APIGroup: "apps"},
			rule:   RiskRule{APIGroups: []string{"*"}},
			want:   false,
		},
		// Policy has wildcard
		{
			name:   "Policy wildcard, rule specific",
			policy: Policy{APIGroup: "*"},
			rule:   RiskRule{APIGroups: []string{"apps"}},
			want:   true,
		},
		{
			name:   "Policy wildcard, rule core",
			policy: Policy{APIGroup: "*"},
			rule:   RiskRule{APIGroups: []string{""}},
			want:   true,
		},
		// Core API group matching
		{
			name:   "Policy core, rule core",
			policy: Policy{APIGroup: ""},
			rule:   RiskRule{APIGroups: []string{""}},
			want:   true,
		},
		{
			name:   "Policy core, rule specific (fail)",
			policy: Policy{APIGroup: ""},
			rule:   RiskRule{APIGroups: []string{"apps"}},
			want:   false,
		},
		{
			name:   "Policy specific, rule core (fail)",
			policy: Policy{APIGroup: "apps"},
			rule:   RiskRule{APIGroups: []string{""}},
			want:   false,
		},
		// Specific matching
		{
			name:   "Policy specific, rule specific (match)",
			policy: Policy{APIGroup: "apps"},
			rule:   RiskRule{APIGroups: []string{"apps", "extensions"}},
			want:   true,
		},
		{
			name:   "Policy specific, rule specific (no match)",
			policy: Policy{APIGroup: "batch"},
			rule:   RiskRule{APIGroups: []string{"apps", "extensions"}},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAPIGroups(&tt.policy, &tt.rule); got != tt.want {
				t.Errorf("matchesAPIGroups() = %v, want %v for policy %v and rule %v", got, tt.want, tt.policy, tt.rule.APIGroups)
			}
		})
	}
}

func TestMatchesResources(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		rule   RiskRule
		want   bool
	}{
		// Rule has wildcard
		{
			name:   "Rule wildcard, policy wildcard",
			policy: Policy{Resource: "*"},
			rule:   RiskRule{Resources: []string{"*"}},
			want:   true,
		},
		{
			name:   "Rule wildcard, policy specific (fail)",
			policy: Policy{Resource: "pods"},
			rule:   RiskRule{Resources: []string{"*"}},
			want:   false,
		},
		// Policy has wildcard
		{
			name:   "Policy wildcard, rule specific",
			policy: Policy{Resource: "*"},
			rule:   RiskRule{Resources: []string{"pods"}},
			want:   true,
		},
		// Specific matching
		{
			name:   "Policy specific, rule specific (match)",
			policy: Policy{Resource: "pods"},
			rule:   RiskRule{Resources: []string{"pods", "deployments"}},
			want:   true,
		},
		{
			name:   "Policy specific, rule specific (no match)",
			policy: Policy{Resource: "services"},
			rule:   RiskRule{Resources: []string{"pods", "deployments"}},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesResources(&tt.policy, &tt.rule); got != tt.want {
				t.Errorf("matchesResources() = %v, want %v for policy %v and rule %v", got, tt.want, tt.policy, tt.rule.Resources)
			}
		})
	}
}

func TestMatchesVerbs(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		rule   RiskRule
		want   bool
	}{
		// Rule has wildcard
		{
			name:   "Rule wildcard, policy wildcard",
			policy: Policy{Verbs: []string{"*"}},
			rule:   RiskRule{Verbs: []string{"*"}},
			want:   true,
		},
		{
			name:   "Rule wildcard, policy specific (fail)",
			policy: Policy{Verbs: []string{"get"}},
			rule:   RiskRule{Verbs: []string{"*"}},
			want:   false,
		},
		// Policy has wildcard
		{
			name:   "Policy wildcard, rule specific",
			policy: Policy{Verbs: []string{"*"}},
			rule:   RiskRule{Verbs: []string{"get"}},
			want:   true,
		},
		// Specific matching (subset)
		{
			name:   "Policy verbs superset of rule verbs",
			policy: Policy{Verbs: []string{"get", "list", "watch"}},
			rule:   RiskRule{Verbs: []string{"get", "list"}},
			want:   true,
		},
		{
			name:   "Policy verbs exact match rule verbs",
			policy: Policy{Verbs: []string{"get", "list"}},
			rule:   RiskRule{Verbs: []string{"get", "list"}},
			want:   true,
		},
		{
			name:   "Policy verbs subset of rule verbs (fail)",
			policy: Policy{Verbs: []string{"get"}},
			rule:   RiskRule{Verbs: []string{"get", "list"}},
			want:   false,
		},
		{
			name:   "Policy verbs no overlap with rule verbs (fail)",
			policy: Policy{Verbs: []string{"update"}},
			rule:   RiskRule{Verbs: []string{"get", "list"}},
			want:   false,
		},
		{
			name:   "Policy verbs has one match, one miss (fail)",
			policy: Policy{Verbs: []string{"get", "update"}},
			rule:   RiskRule{Verbs: []string{"get", "list"}},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesVerbs(&tt.policy, &tt.rule); got != tt.want {
				t.Errorf("matchesVerbs() = %v, want %v for policy %v and rule %v", got, tt.want, tt.policy, tt.rule.Verbs)
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
			wantMatchesCount: 3,
		},
		{
			name:             "Cluster admin access",
			fixture:          "testdata/fixtures/cluster-admin-access.yaml",
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 105,
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
