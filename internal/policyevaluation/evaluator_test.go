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
				RoleType: "Role",
				APIGroup: "",
				Resource: "pods/portforward",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "ClusterRole with full wildcard access should match highest risk rules",
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
			name: "Role with full wildcard access should match high risk rules",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "*",
				Resource:  "*",
				Verbs:     []string{"*"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "ClusterRole with specific pod exec permission should match critical risk rules",
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
			name: "Role with specific pod exec permission should match high risk rules",
			policy: Policy{
				RoleType:  "Role",
				Namespace: "default",
				APIGroup:  "",
				Resource:  "pods/exec",
				Verbs:     []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelHigh,
			wantMatchesCount: 2,
		},
		{
			name: "Non-matching verbs should return base risk level",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"get", "list"}, // Different from rule's create
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelLow,
			wantMatchesCount: 1, // Only base risk level
		},
		{
			name: "Invalid role type should return error",
			policy: Policy{
				RoleType: "InvalidType",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"get"},
			},
			wantErr:          true,
			wantRiskLevel:    RiskLevelLow,
			wantMatchesCount: 0,
		},
		// Test cluster-wide secret access (Critical)
		{
			name: "Cluster-wide secret read",
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
		// Test DaemonSet management (Critical)
		{
			name: "Manage DaemonSets in namespace",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "daemonsets",
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
			wantMatchesCount: 2,
		},
		{
			name: "Empty Namespace Treated as Cluster Scope",
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
		// Test wildcard matches
		{
			name: "Wildcard matches all resources",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "*",
				Verbs:    []string{"create"},
			},
			wantErr:          false,
			wantRiskLevel:    RiskLevelCritical,
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
