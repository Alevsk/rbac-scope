package formatter

import (
	"testing"
)

func TestMatchRiskRule(t *testing.T) {
	// Initialize test rules
	RiskRules = []RiskRule{
		{
			Description: "Read secrets cluster-wide",
			Category:    "Information Disclosure",
			RiskLevel:   RiskLevelCritical,
			APIGroups:   []string{""}, // core API group
			RoleType:    "ClusterRole",
			Resources:   []string{"secrets"},
			Verbs:       []string{"get", "list", "watch"},
			Tags:        []RiskTag{"ClusterWideSecretAccess", "CredentialAccess", "DataExposure", "InformationDisclosure"},
		},
		{
			Description: "Full cluster admin access",
			Category:    "Privilege Escalation",
			RiskLevel:   RiskLevelCritical,
			APIGroups:   []string{"*"},
			RoleType:    "ClusterRole",
			Resources:   []string{"*"},
			Verbs:       []string{"*"},
			Tags:        []RiskTag{"ClusterWideAccess", "PrivilegeEscalation"},
		},
	}

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
		// {
		// 	name: "Full cluster admin should be critical",
		// 	input: SARoleBindingEntry{
		// 		RoleType: "ClusterRole",
		// 		APIGroup: "*",
		// 		Resource: "*",
		// 		Verbs:    []string{"*"},
		// 	},
		// 	wantRisk: RiskLevelCritical,
		// 	wantDesc: "Full cluster admin access",
		// },
		// {
		// 	name: "Limited cluster role should be medium",
		// 	input: SARoleBindingEntry{
		// 		RoleType: "ClusterRole",
		// 		APIGroup: "apps",
		// 		Resource: "deployments",
		// 		Verbs:    []string{"get", "list"},
		// 	},
		// 	wantRisk: RiskLevelMedium,
		// 	wantDesc: "Cluster-wide access with limited resources or verbs",
		// },
		// {
		// 	name: "Namespaced role with limited access should be low",
		// 	input: SARoleBindingEntry{
		// 		RoleType: "Role",
		// 		APIGroup: "apps",
		// 		Resource: "deployments",
		// 		Verbs:    []string{"get", "list"},
		// 	},
		// 	wantRisk: RiskLevelLow,
		// 	wantDesc: "Limited access within namespace",
		// },
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
