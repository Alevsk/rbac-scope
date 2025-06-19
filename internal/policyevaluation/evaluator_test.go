package policyevaluation

import (
	"os"
	"sort"
	"reflect"
	"testing"

	"github.com/alevsk/rbac-ops/internal/config"
	"github.com/alevsk/rbac-ops/internal/logger"
	"gopkg.in/yaml.v3"
)

// Helper function to check if a slice of RiskTags contains a specific tag
func containsTag(tags RiskTags, tag RiskTag) bool {
	for _, T := range tags {
		if T == tag {
			return true
		}
	}
	return false
}

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
		testType      string    // "exact", "count", "resourceNameCheck"
		wantRulesIDs  []int64   // for exact match validation
		wantCount     int       // for count validation or minimal validation
		wantResourceNames []string // for resourceNameCheck
		wantTag       RiskTag   // for resourceNameCheck
	}

	// Preload rules to use in tests, especially for specific ID matching
	allRules := GetRiskRules()
	var sampleCustomRuleForResourceNameTest RiskRule
	// Find a suitable rule, e.g., one for reading secrets in a namespace
	for _, r := range allRules {
		// Let's use a rule that's namespaced and deals with secrets
		// This is just an example, you might need to adjust based on actual rule IDs and definitions
		if r.ID == 1011 { // Example ID for "Read secrets in a namespace"
			sampleCustomRuleForResourceNameTest = r
			break
		}
	}
	if sampleCustomRuleForResourceNameTest.ID == 0 {
		// Fallback or create a dummy rule if not found, to ensure test stability
		// This part might need adjustment based on actual available rules from GetRiskRules()
		// For now, let's assume rule 1011 is "Read secrets in a namespace" (Critical)
		// and its base counterpart is Low (9996) or Medium (9997)
		// If we use a rule that is already Low, the RiskLevelLow override won't be as obvious.
		// Let's use a rule that is typically Critical or High to see the effect.
		// Rule 1011: Read secrets in a namespace, RiskLevelCritical
		// Base Rule for this policy would be Medium (9997)
		sampleCustomRuleForResourceNameTest = RiskRule{
			ID: 1011, Name: "Read secrets in a namespace", RiskLevel: RiskLevelCritical, APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}, RoleType: "Role",
		}
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
			wantRiskLevel: RiskLevelCritical,
			testType:      "count",
			wantCount:     105,
		},
		{
			name: "Cluster-wide pod exec",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"create"}, // Added verbs from YAML
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "count",
			wantCount:     3, // Assuming this matches one specific rule
		},
		{
			name: "Namespaced pod exec",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/exec",
				Verbs:     []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Cluster-wide pod attach",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/attach",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
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
			wantRiskLevel: RiskLevelHigh,
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
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Namespaced pod port-forward",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/portforward",
				Verbs:     []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create pods cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Create pods in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods",
				Verbs:     []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update/Patch pods cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Update/Patch pods in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods",
				Verbs:     []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read secrets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Read secrets in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "secrets",
				Verbs:     []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from Medium to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Modify secrets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Modify secrets in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "secrets",
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from Medium to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Node proxy access (Kubelet API)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/proxy",
				Verbs:    []string{"get", "create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Modify node configuration (labels, taints)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"patch", "update"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Delete nodes",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"delete", "deletecollection"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage PersistentVolumes (cluster-wide storage manipulation)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "persistentvolumes",
				Verbs:    []string{"create", "update", "patch", "delete", "deletecollection"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read pod logs cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/log",
				Verbs:    []string{"get"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Read pod logs in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/log",
				Verbs:     []string{"get"}, // Corrected verbs to match YAML exactly
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage ephemeral containers cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/ephemeralcontainers",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Manage ephemeral containers in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/ephemeralcontainers",
				Verbs:     []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read ConfigMaps cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Read ConfigMaps in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "configmaps",
				Verbs:     []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Modify ConfigMaps cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "configmaps",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical, // Corrected from High to Critical (matches YAML)
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Modify ConfigMaps in a namespace",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "configmaps",
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh, // Corrected from Medium to High (matches YAML)
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Delete namespaces",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []string{"delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage ClusterRoles (create, update, patch, delete)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1027, 9996},
			wantCount:     2,
		},
		{
			name: "Manage ClusterRoleBindings (create, update, patch, delete)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterrolebindings",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1028, 9996},
			wantCount:     2,
		},
		{
			name: "Manage Roles in a namespace (create, update, patch, delete)",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "rbac.authorization.k8s.io",
				Resource:  "roles",
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage RoleBindings in a namespace (create, update, patch, delete)",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "rbac.authorization.k8s.io",
				Resource:  "rolebindings",
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Escalate privileges via ClusterRoles (escalate verb)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"escalate"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1031, 9996},
			wantCount:     2,
		},
		{
			name: "Bind ClusterRoles to identities (bind verb)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"bind"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1032, 9996},
			wantCount:     2,
		},
		{
			name: "Manage Deployments cluster-wide (potential for privileged pod execution)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1033, 1034, 9996},
			wantCount:     3,
		},
		{
			name: "Manage Deployments in a namespace (potential for privileged pod execution)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage DaemonSets cluster-wide (runs on all nodes, high impact)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "daemonsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1035, 1036, 9996},
			wantCount:     3,
		},
		{
			name: "Manage DaemonSets in a namespace (runs on nodes, high impact)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "daemonsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1036, 9996},
			wantCount:     2,
		},
		{
			name: "Manage StatefulSets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "statefulsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1037, 1038, 9996},
			wantCount:     3,
		},
		{
			name: "Manage StatefulSets in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "apps",
				Resource: "statefulsets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage CronJobs cluster-wide (scheduled privileged execution, persistence)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "batch",
				Resource: "cronjobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1039, 1040, 9996},
			wantCount:     3,
		},
		{
			name: "Manage CronJobs in a namespace (scheduled privileged execution, persistence)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "batch",
				Resource: "cronjobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Jobs cluster-wide (one-off privileged execution)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "batch",
				Resource: "jobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1041, 1042, 9996},
			wantCount:     3,
		},
		{
			name: "Manage Jobs in a namespace (one-off privileged execution)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "batch",
				Resource: "jobs",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage MutatingWebhookConfigurations",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "mutatingwebhookconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1043, 9996},
			wantCount:     2,
		},
		{
			name: "Manage ValidatingWebhookConfigurations",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "validatingwebhookconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1044, 9996},
			wantCount:     2,
		},
		{
			name: "Manage CustomResourceDefinitions",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apiextensions.k8s.io",
				Resource: "customresourcedefinitions",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1045, 9996},
			wantCount:     2,
		},
		{
			name: "Manage APIServices",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apiregistration.k8s.io",
				Resource: "apiservices",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1046, 9996},
			wantCount:     2,
		},
		{
			name: "Create ServiceAccount Tokens",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "authentication.k8s.io",
				Resource: "serviceaccounts/token",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1047, 9996},
			wantCount:     2,
		},
		{
			name: "Create ServiceAccount Tokens (ClusterRole for any SA in any namespace)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authentication.k8s.io",
				Resource: "serviceaccounts/token",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1047, 1048, 9996},
			wantCount:     3,
		},
		{
			name: "Create TokenReviews (validate arbitrary tokens)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authentication.k8s.io",
				Resource: "tokenreviews",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create SubjectAccessReviews (check arbitrary permissions)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "authorization.k8s.io",
				Resource: "subjectaccessreviews",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create LocalSubjectAccessReviews (check permissions in a namespace)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "authorization.k8s.io",
				Resource: "localsubjectaccessreviews",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Approve CertificateSigningRequests",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests/approval",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1052, 9996},
			wantCount:     2,
		},
		{
			name: "Create CertificateSigningRequests",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage (get, list, watch, delete) CertificateSigningRequests",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests",
				Verbs:    []string{"get", "list", "watch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage CSIDrivers (potential node compromise)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "csidrivers",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1055, 9996},
			wantCount:     2,
		},
		{
			name: "Manage StorageClasses",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "storageclasses",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Evict Pods cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "pods/eviction",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Evict Pods in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "policy",
				Resource: "pods/eviction",
				Verbs:    []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage RuntimeClasses",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "node.k8s.io",
				Resource: "runtimeclasses",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1059, 9996},
			wantCount:     2,
		},
		{
			name: "Wildcard permission on all resources cluster-wide (Cluster Admin)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs: []int64{
				1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 9999,
			},
			wantCount: 105,
		},
		{
			name: "Wildcard permission on all resources in a namespace (Namespace Admin)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs: []int64{
				1081, 1036, 1063, 1061, 1047, 1011, 1013, 1034, 1040, 1096, 1025, 1029, 1030, 1076, 1097, 1038, 1021, 1042, 1003, 1091, 1009, 1007, 1103, 1001, 1072, 1074, 1085, 1068, 1023, 1094, 1058, 1019, 1005, 1086, 1087, 1088, 1051, 1101, 9999,
			},
			wantCount: 39,
		},
		{
			name: "Manage ClusterIssuers (cert-manager.io)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "cert-manager.io",
				Resource: "clusterissuers",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1062, 9996},
			wantCount:     2,
		},
		{
			name: "Manage ArgoCD Applications (argoproj.io)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "argoproj.io",
				Resource: "applications",
				Verbs:    []string{"create", "update", "patch", "delete", "sync"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1063, 9996},
			wantCount:     2,
		},
		{
			name: "Manage Cilium ClusterwideNetworkPolicies (cilium.io)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "cilium.io",
				Resource: "ciliumclusterwidenetworkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1064, 9996},
			wantCount:     2,
		},
		{
			name: "Manage ETCDSnapshotFiles (k3s.cattle.io)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "k3s.cattle.io",
				Resource: "etcdsnapshotfiles",
				Verbs:    []string{"get", "list", "create", "update", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1065, 9996},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - users", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "users",
				Verbs:    []string{"impersonate"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 9996},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - groups", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "groups",
				Verbs:    []string{"impersonate"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 9996},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - serviceaccounts", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"impersonate"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 9996},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - userextras", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "userextras",
				Verbs:    []string{"impersonate"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 9996},
			wantCount:     2,
		},
		{
			name: "Impersonate users, groups, or service accounts (cluster-wide) - uids", // Adjusted name for clarity
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "uids",
				Verbs:    []string{"impersonate"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1066, 9996},
			wantCount:     2,
		},
		{
			name: "Manage ServiceAccounts cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Manage ServiceAccounts in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "serviceaccounts",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Patch node status cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/status",
				Verbs:    []string{"patch", "update"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read events cluster-wide (core API group)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "", // Core API group for events
				Resource: "events",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read events cluster-wide (events.k8s.io API group)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "events.k8s.io", // events.k8s.io API group
				Resource: "events",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage NetworkPolicies cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1071, 1072, 9996},
			wantCount:     3,
		},
		{
			name: "Manage NetworkPolicies in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Endpoints or EndpointSlices cluster-wide (core API)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "", // Core API group for Endpoints
				Resource: "endpoints",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1073, 1074, 9996},
			wantCount:     3,
		},
		{
			name: "Manage Endpoints or EndpointSlices cluster-wide (discovery.k8s.io API)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "discovery.k8s.io", // discovery.k8s.io for EndpointSlices
				Resource: "endpointslices",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1073, 1074, 9996},
			wantCount:     3,
		},
		{
			name: "Manage Endpoints or EndpointSlices in a namespace (core API)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "", // Core API group for Endpoints
				Resource: "endpoints",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Endpoints or EndpointSlices in a namespace (discovery.k8s.io API)",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "discovery.k8s.io", // discovery.k8s.io for EndpointSlices
				Resource: "endpointslices",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Services cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "services",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1075, 1076, 9996},
			wantCount:     3,
		},
		{
			name: "Manage Services in a namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "",
				Resource: "services",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - ClusterRoles",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - Roles",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "roles",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - ClusterRoleBindings",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "clusterrolebindings",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read RBAC configuration cluster-wide - RoleBindings",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Resource: "rolebindings",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Use privileged PodSecurityPolicy (deprecated) - policy API group",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "podsecuritypolicies",
				Verbs:    []string{"use"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Use privileged PodSecurityPolicy (deprecated) - extensions API group",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "extensions", // Older API group for PSPs
				Resource: "podsecuritypolicies",
				Verbs:    []string{"use"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1078, 9996},
			wantCount:     2,
		},
		{
			name: "Manage PodDisruptionBudgets cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "policy",
				Resource: "poddisruptionbudgets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Leases cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "coordination.k8s.io",
				Resource: "leases",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1080, 1081, 9996},
			wantCount:     3,
		},
		{
			// Note: The YAML rule "Manage Leases in kube-system or kube-node-lease namespace"
			// implies a Critical risk specifically when bound in those namespaces.
			// This test case uses Namespace: "default". The risk level is correct
			// if your scanner logic elevates risk based on the *binding* namespace.
			name: "Manage Leases in kube-system or kube-node-lease namespace",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "coordination.k8s.io",
				Resource: "leases",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "List Namespaces (Cluster Reconnaissance)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []string{"list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "List ValidatingWebhookConfigurations (Reconnaissance)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "validatingwebhookconfigurations",
				Verbs:    []string{"list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "List MutatingWebhookConfigurations (Reconnaissance)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "admissionregistration.k8s.io",
				Resource: "mutatingwebhookconfigurations",
				Verbs:    []string{"list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create/Update ControllerRevisions (Potential Tampering)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "controllerrevisions",
				Verbs:     []string{"create", "update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Create SelfSubjectRulesReviews (Discover Own Permissions)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "authorization.k8s.io",
				Resource:  "selfsubjectrulesreviews",
				Verbs:     []string{"create"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read LimitRanges (Namespace Information Disclosure)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "",
				Resource:  "limitranges",
				Verbs:     []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read ResourceQuotas (Namespace Information Disclosure)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "",
				Resource:  "resourcequotas",
				Verbs:     []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read All ResourceQuotas (Cluster-wide Information Disclosure)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "resourcequotas",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     3,
		},
		{
			name: "Update CertificateSigningRequest Status (Tampering/DoS)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "certificates.k8s.io",
				Resource: "certificatesigningrequests/status",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage Ingresses (Namespace Service Exposure/Traffic Redirection)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "networking.k8s.io",
				Resource:  "ingresses",
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage IngressClasses (Cluster-wide Traffic Control Tampering)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "ingressclasses",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1092, 9996},
			wantCount:     2,
		},
		{
			name: "Update NetworkPolicy Status (Cluster-wide Tampering)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "networking.k8s.io",
				Resource: "networkpolicies/status",
				Verbs:    []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update PodDisruptionBudget Status (Namespace Tampering/DoS)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "policy",
				Resource:  "poddisruptionbudgets/status",
				Verbs:     []string{"create", "update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read ComponentStatuses (Control Plane Reconnaissance)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "componentstatuses",
				Verbs:    []string{"get", "list"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update Deployment Scale (Resource Abuse/DoS)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "deployments/scale",
				Verbs:     []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Update StatefulSet Scale (Resource Abuse/DoS)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "statefulsets/scale",
				Verbs:     []string{"update", "patch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage FlowSchemas (API Server DoS/Manipulation)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "flowcontrol.apiserver.k8s.io",
				Resource: "flowschemas",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1098, 9996},
			wantCount:     2,
		},
		{
			name: "Manage PriorityLevelConfigurations (API Server DoS/Manipulation)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "flowcontrol.apiserver.k8s.io",
				Resource: "prioritylevelconfigurations",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1099, 9996},
			wantCount:     2,
		},
		{
			name: "Read CSINode Objects (Node & Storage Reconnaissance)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "csinodes",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelMedium,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Read CSIStorageCapacities (Namespace Storage Reconnaissance)",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "storage.k8s.io",
				Resource:  "csistoragecapacities",
				Verbs:     []string{"get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow,
			testType:      "count",
			wantCount:     2,
		},
		{
			name: "Manage VolumeAttachments (Cluster-wide Storage/Node Manipulation)",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "storage.k8s.io",
				Resource: "volumeattachments",
				Verbs:    []string{"create", "update", "patch", "delete", "get", "list", "watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelCritical,
			testType:      "exact",
			wantRulesIDs:  []int64{1102, 9996},
			wantCount:     2,
		},
		{
			name: "Watch All Resources in a Namespace (Broad Information Disclosure)",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "*",
				Resource:  "*",
				Verbs:     []string{"watch"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelHigh,
			testType:      "exact",
			wantRulesIDs:  []int64{1103, 9997}, // Base rule for namespaced, wildcard resource/verb is Medium (9997)
		},
		// New tests for resourceNames evaluation
		{
			name: "Policy with specific resourceNames matching custom rule (secrets)",
			policy: Policy{
				RoleType:      "Role",
				Namespace:     "default",
				APIGroup:      sampleCustomRuleForResourceNameTest.APIGroups[0], // ""
				Resource:      sampleCustomRuleForResourceNameTest.Resources[0], // "secrets"
				Verbs:         sampleCustomRuleForResourceNameTest.Verbs,      // {"get", "list", "watch"}
				ResourceNames: []string{"my-secret"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Risk should be overridden to Low
			testType:      "resourceNameCheck",
			// Expecting the custom rule (e.g., 1011) and its corresponding base rule (e.g. 9997 for medium, or 9996 for low if all specific)
			// Since ResourceNames are present, the custom rule 1011 will be RiskLevelLow.
			// The base rule determined by determineBaseRiskRule for this policy (specific, namespaced) would be BaseRiskRuleLow (9996).
			wantRulesIDs:      []int64{sampleCustomRuleForResourceNameTest.ID, BaseRiskRuleLow.ID},
			wantResourceNames: []string{"my-secret"},
			wantTag:           ResourceNameRestricted,
			wantCount:     2, // Custom rule + Base rule
		},
		{
			name: "Policy with specific resourceNames, no custom rule match, base rule modified",
			policy: Policy{
				RoleType:      "Role",
				Namespace:     "default",
				APIGroup:      "nonexistent.group.io", // Should not match any custom rule
				Resource:      "nonexistentresource",
				Verbs:         []string{"get"},
				ResourceNames: []string{"my-specific-resource"},
			},
			wantErr:       false,
			wantRiskLevel: RiskLevelLow, // Base rule risk should be overridden to Low
			testType:      "resourceNameCheck",
			// Only the base rule should be returned, modified.
			// The base rule for a namespaced, specific resource/verb policy is BaseRiskRuleLow (ID 9996).
			wantRulesIDs:      []int64{BaseRiskRuleLow.ID},
			wantResourceNames: []string{"my-specific-resource"},
			wantTag:           ResourceNameRestricted,
			wantCount:     1,
		},
		{
			name: "Policy with empty resourceNames [] - existing behavior (secrets example)",
			policy: Policy{
				RoleType:      "Role",
				Namespace:     "default",
				APIGroup:      sampleCustomRuleForResourceNameTest.APIGroups[0],
				Resource:      sampleCustomRuleForResourceNameTest.Resources[0],
				Verbs:         sampleCustomRuleForResourceNameTest.Verbs,
				ResourceNames: []string{}, // Empty slice
			},
			wantErr:       false,
			wantRiskLevel: sampleCustomRuleForResourceNameTest.RiskLevel, // Should be original risk of custom rule
			testType:      "exact", // Or "count" if IDs are not stable/known for this test setup
			// Expecting custom rule + original base rule.
			// Original rule 1011 is Critical. Base rule for this (namespaced, specific) is Low (9996)
			// This seems off, "Read secrets in a namespace" (1011) is Critical, but base rule for specific namespaced is Low.
			// Let's use the values from existing tests for "Read secrets in a namespace" (ID 1011)
			// It expects RiskLevelCritical and count 2.
			// Existing test: "Read secrets in a namespace" -> wantRiskLevel: RiskLevelCritical, wantCount: 2
			// This implies the base rule is also critical or the custom rule is the only one determining the highest.
			// The base rule for (Role, default, "", secrets, [get,list,watch]) is BaseRiskRuleLow (9996).
			// So, if 1011 (Critical) matches, results are [1011, 9996]. Highest is Critical.
			wantRulesIDs:  []int64{sampleCustomRuleForResourceNameTest.ID, BaseRiskRuleLow.ID},
			wantCount:     2,
		},
		{
			name: "Policy with resourceNames [\"\"] - existing behavior (secrets example)",
			policy: Policy{
				RoleType:      "Role",
				Namespace:     "default",
				APIGroup:      sampleCustomRuleForResourceNameTest.APIGroups[0],
				Resource:      sampleCustomRuleForResourceNameTest.Resources[0],
				Verbs:         sampleCustomRuleForResourceNameTest.Verbs,
				ResourceNames: []string{""}, // Slice with one empty string
			},
			wantErr:       false,
			wantRiskLevel: sampleCustomRuleForResourceNameTest.RiskLevel,
			testType:      "exact",
			wantRulesIDs:  []int64{sampleCustomRuleForResourceNameTest.ID, BaseRiskRuleLow.ID},
			wantCount:     2,
		},
		{
			name: "Policy with nil resourceNames - existing behavior (secrets example)",
			policy: Policy{
				RoleType:      "Role",
				Namespace:     "default",
				APIGroup:      sampleCustomRuleForResourceNameTest.APIGroups[0],
				Resource:      sampleCustomRuleForResourceNameTest.Resources[0],
				Verbs:         sampleCustomRuleForResourceNameTest.Verbs,
				ResourceNames: nil, // Nil slice
			},
			wantErr:       false,
			wantRiskLevel: sampleCustomRuleForResourceNameTest.RiskLevel,
			testType:      "exact",
			wantRulesIDs:  []int64{sampleCustomRuleForResourceNameTest.ID, BaseRiskRuleLow.ID},
			wantCount:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchRiskRules(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchRiskRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) == 0 && (tt.testType == "exact" || tt.testType == "resourceNameCheck" || tt.wantCount > 0) {
				t.Errorf("MatchRiskRules() returned no rules, but expected some.")
				return
			}

			if len(got) > 0 && got[0].RiskLevel != tt.wantRiskLevel {
				// For resourceNameCheck, the primary matched rule (custom or base) should have its risk level checked.
				// The overall highest risk (got[0]) might be from an unmodified base rule if a resource-restricted custom rule is matched.
				// Let's refine this check for resourceNameCheck.
				if tt.testType == "resourceNameCheck" {
					// Find the rule that should have been modified (either a custom match or the base rule)
					var modifiedRule RiskRule
					isCustomMatch := false
					if len(tt.wantRulesIDs) == 1 && tt.wantRulesIDs[0] == BaseRiskRuleLow.ID { // Only base rule expected and modified
						modifiedRule = got[0] // Assuming base rule is the only one, or the first one if sorted.
					} else {
						for _, r := range got {
							// Check if this rule is one of the expected custom rules that should be modified
							for _, expectedID := range tt.wantRulesIDs {
								if r.ID == expectedID && r.ID != BaseRiskRuleLow.ID && r.ID != BaseRiskRuleMedium.ID && r.ID != BaseRiskRuleHigh.ID && r.ID != BaseRiskRuleCritical.ID {
									modifiedRule = r
									isCustomMatch = true
									break
								}
							}
							if isCustomMatch {break}
						}
						if !isCustomMatch && len(got) > 0 { // If no custom rule matched and modified, check the base rule from the results
							for _, r := range got {
								if r.ID == BaseRiskRuleLow.ID || r.ID == BaseRiskRuleMedium.ID || r.ID == BaseRiskRuleHigh.ID || r.ID == BaseRiskRuleCritical.ID {
									// This logic might need to be more specific if multiple base rules could be involved or if sorting changes
									// For now, assume the relevant base rule is identifiable
									 isBaseOnlyScenario := true
									 for _, id := range tt.wantRulesIDs {
										 if id != BaseRiskRuleLow.ID && id != BaseRiskRuleMedium.ID && id != BaseRiskRuleHigh.ID && id != BaseRiskRuleCritical.ID {
											isBaseOnlyScenario = false
											break
										 }
									 }
									 if isBaseOnlyScenario {
										 modifiedRule = r // Check the base rule that was modified
										 break
									 }
								}
							}
						}
					}

					if modifiedRule.ID != 0 && modifiedRule.RiskLevel != tt.wantRiskLevel {
						t.Errorf("MatchRiskRules() specific rule ID %d RiskLevel = %v, want %v for test '%s'", modifiedRule.ID, modifiedRule.RiskLevel, tt.wantRiskLevel, tt.name)
					} else if modifiedRule.ID == 0 && len(got) > 0 {
                         // If we couldn't identify a specific modified rule, but expected one, this is an issue.
                         // However, if the highest level already matches, it might be okay for some scenarios.
                         // This part of the check is complex due to multiple rules being returned.
                         // Fallback to checking got[0] if specific rule not found, but log it.
                        // For now, let's rely on the got[0].RiskLevel check if specific modified rule logic is not perfect.
                        if got[0].RiskLevel != tt.wantRiskLevel {
						    t.Logf("Could not identify the specifically modified rule for detailed RiskLevel check in test '%s'. Checking got[0].RiskLevel.", tt.name)
						    t.Errorf("MatchRiskRules() highest risk level = %v, want %v for test '%s'", got[0].RiskLevel, tt.wantRiskLevel, tt.name)
                        }
					} else if modifiedRule.ID == 0 && len(got) == 0 && tt.wantCount > 0 {
                        t.Errorf("MatchRiskRules() returned no rules, but expected specific rule with RiskLevel %v for test '%s'", tt.wantRiskLevel, tt.name)
                    }

				} else if got[0].RiskLevel != tt.wantRiskLevel {
					t.Errorf("MatchRiskRules() highest risk level = %v, want %v for test '%s'", got[0].RiskLevel, tt.wantRiskLevel, tt.name)
				}
			} else if len(got) == 0 && tt.wantCount > 0 {
				t.Errorf("MatchRiskRules() returned no rules, but wantCount was %d for test '%s'", tt.wantCount, tt.name)
			}


			// Handle different test types
			switch tt.testType {
			case "exact":
				if !compareRiskRules(got, tt.wantRulesIDs) {
					ruleIds := []int64{}
					for _, rule := range got {
						ruleIds = append(ruleIds, rule.ID)
					}
					// Sort ruleIds before comparing for consistent error messages
					sort.Slice(ruleIds, func(i, j int) bool { return ruleIds[i] < ruleIds[j] })
					// tt.wantRulesIDs should also be sorted if not already
					sort.Slice(tt.wantRulesIDs, func(i, j int) bool { return tt.wantRulesIDs[i] < tt.wantRulesIDs[j] })
					t.Errorf("MatchRiskRules() got IDs = %v, want IDs = %v for test '%s'", ruleIds, tt.wantRulesIDs, tt.name)
				}
			case "count":
				if len(got) != tt.wantCount {
					ruleIds := []int64{}
					for _, rule := range got {
						ruleIds = append(ruleIds, rule.ID)
					}
					t.Errorf("MatchRiskRules() got %v rules (IDs: %v), want %v for test '%s'", len(got), ruleIds, tt.wantCount, tt.name)
				}
			case "resourceNameCheck":
				if len(got) != tt.wantCount {
					t.Errorf("MatchRiskRules() got %v rules, want %v for resourceNameCheck test '%s'", len(got), tt.wantCount, tt.name)
				}
				// Check specific properties of the matched rule(s)
				// This part assumes that if a custom rule matches, it's the one we care about for these properties.
				// If only a base rule matches, that's the one.
				var ruleToCheck RiskRule
				foundRule := false
				if len(tt.wantRulesIDs) == 1 && tt.wantRulesIDs[0] == BaseRiskRuleLow.ID { // Only base rule expected
					for _, r := range got {
						if r.ID == BaseRiskRuleLow.ID {
							ruleToCheck = r
							foundRule = true
							break
						}
					}
				} else { // Expecting a custom rule (potentially among others)
					expectedCustomRuleID := int64(-1)
					for _, id := range tt.wantRulesIDs {
						isBase := false
						for _, baseID := range []int64{BaseRiskRuleCritical.ID, BaseRiskRuleHigh.ID, BaseRiskRuleMedium.ID, BaseRiskRuleLow.ID} {
							if id == baseID {
								isBase = true
								break
							}
						}
						if !isBase {
							expectedCustomRuleID = id
							break
						}
					}

					if expectedCustomRuleID != -1 {
						for _, r := range got {
							if r.ID == expectedCustomRuleID {
								ruleToCheck = r
								foundRule = true
								break
							}
						}
					} else if len(got) > 0 { // Fallback if no specific custom ID, check the first non-base if possible, or just first
						 isNonBaseFound := false
						 for _, r := range got {
							 isBase := false
							 for _, baseID := range []int64{BaseRiskRuleCritical.ID, BaseRiskRuleHigh.ID, BaseRiskRuleMedium.ID, BaseRiskRuleLow.ID} {
								 if r.ID == baseID {
									 isBase = true
									 break
								 }
							 }
							 if !isBase {
								 ruleToCheck = r
								 foundRule = true
								 isNonBaseFound = true
								 break
							 }
						 }
						 if !isNonBaseFound && len(got) > 0 { // if all are base rules (e.g. only base rule scenario)
							 ruleToCheck = got[0] // Pick the first one (highest risk, which should be the modified base)
							 foundRule = true
						 }
					}
				}

				if !foundRule && len(got) > 0 {
					// If no specific rule was identified based on IDs, but we have results,
					// and we expect resource names to be present, pick the first rule that has them.
					// This is a fallback, ideally ID matching is better.
					for _, r := range got {
						if len(r.ResourceNames) > 0 {
							ruleToCheck = r
							foundRule = true
							break;
						}
					}
					if !foundRule { // If still not found, and we expected one, use the highest risk rule.
                        ruleToCheck = got[0]
                        foundRule = true
                    }
				} else if !foundRule && len(got) == 0 && tt.wantCount > 0 {
                     t.Errorf("MatchRiskRules() returned no rules, but expected one for resourceNameCheck in test '%s'", tt.name)
                }


				if foundRule {
					if ruleToCheck.RiskLevel != tt.wantRiskLevel {
						t.Errorf("MatchRiskRules() rule ID %d (name: %s) RiskLevel = %s, want %s for test '%s'", ruleToCheck.ID, ruleToCheck.Name, ruleToCheck.RiskLevel, tt.wantRiskLevel, tt.name)
					}
					if !containsTag(ruleToCheck.Tags, tt.wantTag) {
						t.Errorf("MatchRiskRules() rule ID %d (name: %s) Tags = %v, want to contain %s for test '%s'", ruleToCheck.ID, ruleToCheck.Name, ruleToCheck.Tags, tt.wantTag, tt.name)
					}
					if !reflect.DeepEqual(ruleToCheck.ResourceNames, tt.wantResourceNames) {
						t.Errorf("MatchRiskRules() rule ID %d (name: %s) ResourceNames = %v, want %v for test '%s'", ruleToCheck.ID, ruleToCheck.Name, ruleToCheck.ResourceNames, tt.wantResourceNames, tt.name)
					}
				} else if tt.wantCount > 0 { // If no rule was found to check, but we expected rules
					t.Errorf("MatchRiskRules() did not find a suitable rule to check for resourceNameCheck assertions in test '%s'", tt.name)
				}

			default:
				t.Errorf("Invalid test type: %v for test '%s'", tt.testType, tt.name)
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
			if got := determineBaseRiskRule(&tt.policy); got.RiskLevel != tt.want {
				t.Errorf("determineBaseRiskLevel() = %v, want %v", got.RiskLevel, tt.want)
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
