package policyevaluation

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMatchRiskRules(t *testing.T) {
	// We'll use the actual risk rules from risks.yaml
	rules := GetRiskRules()
	if len(rules) == 0 {
		t.Fatal("No risk rules loaded from risks.yaml")
	}
	// Test wildcard cases
	tests := []struct {
		name    string
		policy  Policy
		want    []RiskRule
		wantErr bool
	}{
		{
			name: "Wildcard permission on all resources cluster-wide",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			want: []RiskRule{
				{
					Name:      "Wildcard permission on all resources cluster-wide (Cluster Admin)",
					RiskLevel: RiskLevelCritical,
					RoleType:  "ClusterRole",
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{
					Name:      "Base Risk Level: 3",
					RiskLevel: RiskLevelCritical,
				},
			},
			wantErr: false,
		},
		{
			name: "Wildcard permission on all resources in namespace",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "*",
				Resource:  "*",
				Verbs:     []string{"*"},
			},
			want: []RiskRule{
				{
					Name:      "Wildcard permission on all resources in a namespace (Namespace Admin)",
					RiskLevel: RiskLevelHigh,
					RoleType:  "Role",
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{
					Name:      "Base Risk Level: 2",
					RiskLevel: RiskLevelHigh,
				},
			},
			wantErr: false,
		},
		{
			name: "Cluster-wide pod exec",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"create"},
			},
			want: []RiskRule{
				{
					Name:      "Execute into pods cluster-wide (potential container escape)",
					RiskLevel: RiskLevelCritical,
					RoleType:  "ClusterRole",
				},
			},
			wantErr: false,
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
			want: []RiskRule{
				{
					Name:      "Execute into pods in a namespace (potential container escape)",
					RiskLevel: RiskLevelHigh,
					RoleType:  "Role",
					APIGroups: []string{},
					Resources: []string{"pods/exec"},
					Verbs:     []string{"create"},
				},
				{Name: "Base Risk Level: 0", RiskLevel: RiskLevelLow},
			},
			wantErr: false,
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
			want: []RiskRule{
				{
					Name:      "Read secrets cluster-wide",
					RiskLevel: RiskLevelCritical,
					RoleType:  "ClusterRole",
					APIGroups: []string{},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{Name: "Base Risk Level: 0", RiskLevel: RiskLevelLow},
			},
			wantErr: false,
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
			want: []RiskRule{
				{
					Name:      "Manage DaemonSets in a namespace (runs on nodes, high impact)",
					RiskLevel: RiskLevelCritical,
					RoleType:  "Role",
					APIGroups: []string{"apps"},
					Resources: []string{"daemonsets"},
					Verbs:     []string{"create", "update", "patch", "delete"},
				},
				{Name: "Base Risk Level: 0", RiskLevel: RiskLevelLow},
			},
			wantErr: false,
		},
		// Test negative cases
		{
			name: "Invalid Role Type",
			policy: Policy{
				RoleType: "InvalidType",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"get"},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Empty Namespace Treated as Cluster Scope",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			want: []RiskRule{
				{
					Name:      "Wildcard permission on all resources cluster-wide (Cluster Admin)",
					RiskLevel: RiskLevelCritical,
					RoleType:  "ClusterRole",
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{Name: "Base Risk Level: 3", RiskLevel: RiskLevelCritical},
			},
		},
		// Test negative cases
		{
			name: "Invalid Role Type",
			policy: Policy{
				RoleType: "InvalidType",
				APIGroup: "apps",
				Resource: "deployments",
				Verbs:    []string{"get"},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Empty Namespace Treated as Cluster Scope",
			policy: Policy{
				RoleType: "Role",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			want: []RiskRule{
				{
					Name:      "Wildcard permission on all resources cluster-wide (Cluster Admin)",
					RiskLevel: RiskLevelCritical,
					RoleType:  "ClusterRole",
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
				{Name: "Base Risk Level: 3", RiskLevel: RiskLevelCritical},
			},
			wantErr: false,
		},
		// Test non-matching verbs
		{
			name: "Non-matching verbs for pod exec",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "",
				Resource: "pods/exec",
				Verbs:    []string{"get", "list"}, // Different from rule's create
			},
			want: []RiskRule{
				{Name: "Base Risk Level: 0", RiskLevel: RiskLevelLow},
			},
			wantErr: false,
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
			want: []RiskRule{
				{Name: "Base Risk Level: 2", RiskLevel: RiskLevelHigh},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchRiskRules(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchRiskRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Check that all expected rules are present
			for _, wantRule := range tt.want {
				found := false
				for _, gotRule := range got {
					if gotRule.Name == wantRule.Name && gotRule.RiskLevel == wantRule.RiskLevel {
						// For base risk level rules, only check name and risk level
						if strings.HasPrefix(wantRule.Name, "Base Risk Level:") {
							found = true
							break
						}
						// For other rules, check all fields
						if reflect.DeepEqual(gotRule, wantRule) {
							found = true
							break
						}
					}
				}
				if !found {
					t.Errorf("MatchRiskRules() missing expected rule: %v", wantRule)
				}
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
		name            string
		fixturePath     string
		expectedMatches []struct {
			ruleName  string
			riskLevel RiskLevel
		}
	}{
		{
			name:        "Secrets reader cluster role",
			fixturePath: "testdata/fixtures/secrets-reader.yaml",
			expectedMatches: []struct {
				ruleName  string
				riskLevel RiskLevel
			}{
				{
					ruleName:  "Read secrets cluster-wide",
					riskLevel: RiskLevelCritical,
				},
				{
					ruleName:  "Base Risk Level: 0",
					riskLevel: RiskLevelLow,
				},
			},
		},
		{
			name:        "Cluster admin access",
			fixturePath: "testdata/fixtures/cluster-admin-access.yaml",
			expectedMatches: []struct {
				ruleName  string
				riskLevel RiskLevel
			}{
				{
					ruleName:  "Wildcard permission on all resources cluster-wide (Cluster Admin)",
					riskLevel: RiskLevelCritical,
				},
				{
					ruleName:  "Base Risk Level: 3",
					riskLevel: RiskLevelCritical,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Read and parse the fixture file
			fixtureBytes, err := os.ReadFile(tt.fixturePath)
			if err != nil {
				t.Fatalf("Failed to read fixture file: %v", err)
			}

			var role K8sRole
			if err := yaml.Unmarshal(fixtureBytes, &role); err != nil {
				t.Fatalf("Failed to parse YAML: %v", err)
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
				t.Logf("Processing rule: %+v", rule)

				// For cluster-admin-like access, if any value is "*", use that
				policy.APIGroup = ""
				for _, apiGroup := range rule.APIGroups {
					t.Logf("Checking APIGroup: %s", apiGroup)
					if apiGroup == "*" {
						policy.APIGroup = "*"
						t.Logf("Found wildcard APIGroup, setting to *")
						break
					}
					if policy.APIGroup == "" {
						policy.APIGroup = apiGroup
						t.Logf("Setting APIGroup to: %s", apiGroup)
					}
				}
				t.Logf("Final APIGroup: %s", policy.APIGroup)

				policy.Resource = ""
				for _, resource := range rule.Resources {
					t.Logf("Checking Resource: %s", resource)
					if resource == "*" {
						policy.Resource = "*"
						t.Logf("Found wildcard Resource, setting to *")
						break
					}
					if policy.Resource == "" {
						policy.Resource = resource
						t.Logf("Setting Resource to: %s", resource)
					}
				}
				t.Logf("Final Resource: %s", policy.Resource)

				policy.Verbs = rule.Verbs
				t.Logf("Final Verbs: %v", policy.Verbs)
			}

			// Print all risk rules for debugging
			t.Logf("Available risk rules:")
			for _, rr := range GetRiskRules() {
				t.Logf("  - %s (Type: %s, APIGroups: %v, Resources: %v, Verbs: %v)",
					rr.Name, rr.RoleType, rr.APIGroups, rr.Resources, rr.Verbs)
			}

			// Evaluate the policy
			t.Logf("Evaluating policy: %+v", policy)
			matches, err := MatchRiskRules(policy)
			if err != nil {
				t.Fatalf("Failed to evaluate policy: %v", err)
			}
			t.Logf("Got matches: %+v", matches)

			// Verify number of matches
			if len(matches) != len(tt.expectedMatches) {
				t.Errorf("Expected %d matches, got %d", len(tt.expectedMatches), len(matches))
				t.Logf("Expected matches:")
				for _, m := range tt.expectedMatches {
					t.Logf("  - %s (Risk Level: %v)", m.ruleName, m.riskLevel)
				}
				t.Logf("Got matches:")
				for _, m := range matches {
					t.Logf("  - %s (Risk Level: %v)", m.Name, m.RiskLevel)
				}
				return
			}

			// Verify each expected match
			for i, expected := range tt.expectedMatches {
				if i >= len(matches) {
					t.Errorf("Missing expected match: %s", expected.ruleName)
					continue
				}

				got := matches[i]
				if got.Name != expected.ruleName {
					t.Errorf("Expected match %d to have name %q, got %q", i, expected.ruleName, got.Name)
				}
				if got.RiskLevel != expected.riskLevel {
					t.Errorf("Expected match %d to have risk level %v, got %v", i, expected.riskLevel, got.RiskLevel)
				}
			}
		})
	}
}
