package formatter

import (
	"strings"
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

type RiskRule struct {
	Description string
	Category    string
	RiskLevel   RiskLevel
	APIGroups   []string
	RoleType    string
	Resources   []string
	Verbs       []string
}

var RiskRules = []RiskRule{}

// MatchRiskRule checks if a table row matches any of the defined risk rules
// and returns the matching rule or nil if no match is found
func MatchRiskRule(row SARoleBindingEntry) *RiskRule {
	// First, determine the base risk level based on role type and wildcards
	var baseRisk RiskLevel
	var description string
	var category string

	// Determine base risk based on role type and scope
	if row.RoleType == "ClusterRole" {
		if row.APIGroup == "*" {
			// Cluster-wide access across all namespaces and all API groups
			baseRisk = RiskLevelCritical
			description = "Cluster-wide access across all namespaces and all API groups"
			category = "Broad Cluster Access"
		} else if row.Resource == "*" && contains(row.Verbs, "*") {
			// Cluster-wide access but limited to specific API group
			baseRisk = RiskLevelHigh
			description = "Cluster-wide access across all namespaces but limited to specific API group"
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

	// Now check for specific rules that might increase the risk level
	for _, rule := range RiskRules {
		// Skip rules that don't match the role type
		if rule.RoleType != row.RoleType {
			continue
		}

		// Check if the rule matches
		matches := true

		// API Groups: match if row has wildcard or matches rule
		if row.APIGroup != "*" && !contains(rule.APIGroups, row.APIGroup) {
			matches = false
		}

		// Resources: match if row has wildcard or matches rule
		if row.Resource != "*" && !contains(rule.Resources, row.Resource) {
			matches = false
		}

		// Verbs: match if row has wildcard or all verbs match rule
		if !contains(row.Verbs, "*") {
			for _, verb := range row.Verbs {
				verb = strings.TrimSpace(verb)
				if !contains(rule.Verbs, verb) {
					matches = false
					break
				}
			}
		}

		// If rule matches and has higher risk, upgrade the risk level and details
		if matches && rule.RiskLevel > resultRule.RiskLevel {
			resultRule.RiskLevel = rule.RiskLevel
			resultRule.Description = rule.Description
			resultRule.Category = rule.Category
		}
	}

	return resultRule
}
