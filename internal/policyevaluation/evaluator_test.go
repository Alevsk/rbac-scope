package policyevaluation

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMatchRiskRules(t *testing.T) {
	// Save original rules and restore them after test
	originalRules := RiskRules
	defer func() { RiskRules = originalRules }()

	// Setup test custom rules
	RiskRules = []RiskRule{
		{
			Name:      "High Risk Custom Rule",
			RiskLevel: RiskLevelHigh,
			RoleType:  "ClusterRole",
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"create", "delete"},
		},
		{
			Name:      "Medium Risk Custom Rule",
			RiskLevel: RiskLevelMedium,
			RoleType:  "Role",
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		},
	}

	tests := []struct {
		name    string
		policy  Policy
		want    []RiskRule
		wantErr bool
	}{
		{
			name: "Critical Risk - Cluster Wide Access with Wildcards",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "*",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			want: []RiskRule{
				{Name: "Base Risk Level: 3", RiskLevel: RiskLevelCritical},
			},
			wantErr: false,
		},
		{
			name: "High Risk - Cluster Wide with Some Wildcards",
			policy: Policy{
				RoleType: "ClusterRole",
				APIGroup: "apps",
				Resource: "*",
				Verbs:    []string{"*"},
			},
			want: []RiskRule{
				{
					Name:      "High Risk Custom Rule",
					RiskLevel: RiskLevelHigh,
					RoleType:  "ClusterRole",
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
					Verbs:     []string{"create", "delete"},
				},
				{Name: "Base Risk Level: 2", RiskLevel: RiskLevelHigh},
			},
			wantErr: false,
		},
		{
			name: "Medium Risk - Namespaced with Some Wildcards",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "",
				Resource:  "*",
				Verbs:     []string{"*"},
			},
			want: []RiskRule{
				{
					Name:      "Medium Risk Custom Rule",
					RiskLevel: RiskLevelMedium,
					RoleType:  "Role",
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list"},
				},
				{Name: "Base Risk Level: 1", RiskLevel: RiskLevelMedium},
			},
			wantErr: false,
		},
		{
			name: "Low Risk - Namespaced without Wildcards",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "deployments",
				Verbs:     []string{"get", "list"},
			},
			want: []RiskRule{
				{Name: "Base Risk Level: 0", RiskLevel: RiskLevelLow},
			},
			wantErr: false,
		},
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
				{Name: "Base Risk Level: 3", RiskLevel: RiskLevelCritical},
			},
			wantErr: false,
		},
		{
			name: "Multiple Wildcards in Verbs",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "deployments",
				Verbs:     []string{"get", "*", "list"},
			},
			want: []RiskRule{
				{Name: "Base Risk Level: 1", RiskLevel: RiskLevelMedium},
			},
			wantErr: false,
		},
		{
			name: "Partial Wildcard in Resource Name",
			policy: Policy{
				Namespace: "default",
				RoleType:  "Role",
				APIGroup:  "apps",
				Resource:  "deploy*",
				Verbs:     []string{"get", "list"},
			},
			want: []RiskRule{
				{Name: "Base Risk Level: 1", RiskLevel: RiskLevelMedium},
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MatchRiskRules() = %v, want %v", got, tt.want)
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
		// Add more test cases here for other fixture files
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
				policy.APIGroup = ""
				if len(rule.APIGroups) > 0 {
					policy.APIGroup = rule.APIGroups[0]
				}
				if len(rule.Resources) > 0 {
					policy.Resource = rule.Resources[0]
				}
				policy.Verbs = rule.Verbs
			}

			// Evaluate the policy
			matches, err := MatchRiskRules(policy)
			if err != nil {
				t.Fatalf("Failed to evaluate policy: %v", err)
			}

			// Verify number of matches
			if len(matches) != len(tt.expectedMatches) {
				t.Errorf("Expected %d matches, got %d", len(tt.expectedMatches), len(matches))
				t.Logf("Got matches: %+v", matches)
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
