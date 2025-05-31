package formatter

import (
	"testing"
)

func TestMatchRiskRule(t *testing.T) {

	tests := []struct {
		name     string
		input    SARoleBindingEntry
		wantRisk RiskLevel
		wantDesc string
	}{
		{
			name: "Secrets reader cluster role should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "", // core API group
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Read secrets cluster-wide",
		},
		{
			name: "Real input test case",
			input: SARoleBindingEntry{
				ServiceAccountName: "secrets-reader",
				Namespace:          "default",
				RoleType:           "ClusterRole",
				RoleName:           "secrets-reader",
				APIGroup:           "",
				Resource:           "secrets",
				Verbs:              []string{"get", "list", "watch"},
				RiskLevel:          "",
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Read secrets cluster-wide",
		},
		{
			name: "Cluster-wide pod exec should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Cluster-wide pod exec",
		},
		{
			name: "Namespaced pod exec should be high",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Namespaced pod exec",
		},
		{
			name: "Cluster-wide pod attach should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/attach",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Cluster-wide pod attach",
		},
		{
			name: "Namespaced pod attach should be high",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/attach",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Namespaced pod attach",
		},
		{
			name: "Cluster-wide pod port-forward should be high",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/portforward",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Cluster-wide pod port-forward",
		},
		{
			name: "Namespaced pod port-forward should be medium",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/portforward",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelMedium,
			wantDesc: "Namespaced pod port-forward",
		},
		{
			name: "Create pods cluster-wide should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Create pods cluster-wide (potential for privileged pods)",
		},
		{
			name: "Create pods in namespace should be high",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"create"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Create pods in a namespace (potential for privileged pods)",
		},
		{
			name: "Update/Patch pods cluster-wide should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"update", "patch"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Update/Patch pods cluster-wide (can modify to privileged)",
		},
		{
			name: "Update/Patch pods in namespace should be high",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods",
				Verbs:    []string{"update", "patch"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Update/Patch pods in a namespace (can modify to privileged)",
		},
		{
			name: "Read secrets cluster-wide should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Read secrets cluster-wide",
		},
		{
			name: "Read secrets in namespace should be critical",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Read secrets in a namespace",
		},
		{
			name: "Modify secrets cluster-wide should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Modify secrets cluster-wide",
		},
		{
			name: "Modify secrets in namespace should be critical",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Modify secrets in a namespace",
		},
		{
			name: "Node proxy access should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/proxy",
				Verbs:    []string{"get", "create", "update", "patch", "delete"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Node proxy access (Kubelet API)",
		},
		{
			name: "Modify node configuration should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"patch", "update"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Modify node configuration (labels, taints)",
		},
		{
			name: "Delete nodes should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"delete", "deletecollection"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Delete nodes",
		},
		{
			name: "Manage PersistentVolumes should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "persistentvolumes",
				Verbs:    []string{"create", "update", "patch", "delete", "deletecollection"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Manage PersistentVolumes (cluster-wide storage manipulation)",
		},
		{
			name: "Read pod logs cluster-wide should be high",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/log",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Read pod logs cluster-wide",
		},
		{
			name: "Modify secrets cluster-wide should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Modify secrets cluster-wide",
		},
		{
			name: "Modify secrets in namespace should be critical",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "secrets",
				Verbs:    []string{"create", "update", "patch", "delete"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Modify secrets in a namespace",
		},
		{
			name: "Node proxy access should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes/proxy",
				Verbs:    []string{"get", "create", "update", "patch", "delete"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Node proxy access (Kubelet API)",
		},
		{
			name: "Modify node configuration should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"patch", "update"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Modify node configuration (labels, taints)",
		},
		{
			name: "Delete nodes should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "nodes",
				Verbs:    []string{"delete", "deletecollection"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Delete nodes",
		},
		{
			name: "Manage PersistentVolumes should be critical",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "persistentvolumes",
				Verbs:    []string{"create", "update", "patch", "delete", "deletecollection"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Manage PersistentVolumes (cluster-wide storage manipulation)",
		},
		{
			name: "Read pod logs cluster-wide should be high",
			input: SARoleBindingEntry{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/log",
				Verbs:    []string{"get", "list", "watch"},
			},
			wantRisk: RiskLevelHigh,
			wantDesc: "Read pod logs cluster-wide",
		},
		{
			name: "Full access within namespace",
			input: SARoleBindingEntry{
				RoleType: "Role",
				APIGroup: "",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			wantRisk: RiskLevelCritical,
			wantDesc: "Full access within namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing case: %s", tt.name)
			t.Logf("Input: %+v", tt.input)

			got := MatchRiskRule(tt.input)

			if got == nil {
				t.Errorf("MatchRiskRule() = nil, want risk level %v", tt.wantRisk)
				return
			}

			// Debug logging
			t.Logf("Base risk level assigned: %v", got.RiskLevel)
			t.Logf("Checking against %d predefined rules", len(RiskRules))

			if got.RiskLevel != tt.wantRisk {
				t.Errorf("MatchRiskRule() risk level = %v, want %v", got.RiskLevel, tt.wantRisk)
			}
			if got.Description != tt.wantDesc {
				t.Errorf("MatchRiskRule() description = %v, want %v", got.Description, tt.wantDesc)
			}
			t.Logf("Got rule: %+v", got)
		})
	}
}
