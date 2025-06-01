package policyevaluation

import (
	"fmt"
	"sort"
	"strings"
)

// containsWildcard checks if a string equals "*" or contains "*"
func containsWildcard(s string) bool {
	return s == "*" || strings.Contains(s, "*")
}

// containsWildcardInSlice checks if any string in the slice equals "*" or contains "*"
func containsWildcardInSlice(items []string) bool {
	for _, item := range items {
		if containsWildcard(item) {
			return true
		}
	}
	return false
}

// isClusterScoped determines if a policy is cluster-scoped based on RoleType and Namespace
func isClusterScoped(policy *Policy) bool {
	return policy.RoleType == "ClusterRole" || policy.Namespace == ""
}

// determineBaseRiskLevel evaluates a policy against base risk rules
func determineBaseRiskLevel(policy *Policy) RiskLevel {
	// Check for Critical first (cluster-wide + wildcards everywhere)
	if isClusterScoped(policy) &&
		containsWildcard(policy.APIGroup) &&
		containsWildcard(policy.Resource) &&
		containsWildcardInSlice(policy.Verbs) {
		return RiskLevelCritical
	}

	// Check for High (cluster-wide + some wildcards)
	if isClusterScoped(policy) &&
		(containsWildcard(policy.APIGroup) ||
			containsWildcard(policy.Resource) ||
			containsWildcardInSlice(policy.Verbs)) {
		return RiskLevelHigh
	}

	// Check for Medium (namespaced + some wildcards)
	if !isClusterScoped(policy) &&
		(containsWildcard(policy.APIGroup) ||
			containsWildcard(policy.Resource) ||
			containsWildcardInSlice(policy.Verbs)) {
		return RiskLevelMedium
	}

	// Default to Low (namespaced + no wildcards)
	return RiskLevelLow
}

// matchesCustomRule checks if a policy matches a custom risk rule
func matchesCustomRule(policy *Policy, rule *RiskRule) bool {
	// Don't match custom rules for critical risk policies
	if determineBaseRiskLevel(policy) == RiskLevelCritical {
		return false
	}

	// Check RoleType match
	if rule.RoleType != "" && rule.RoleType != policy.RoleType {
		return false
	}

	// Check APIGroups match (rule's APIGroups must be a subset of policy's APIGroup)
	if len(rule.APIGroups) > 0 {
		hasMatch := false
		for _, apiGroup := range rule.APIGroups {
			// Special handling for core API group
			if (apiGroup == "" && policy.APIGroup == "") ||
				apiGroup == policy.APIGroup ||
				containsWildcard(policy.APIGroup) {
				hasMatch = true
				break
			}
		}
		if !hasMatch {
			return false
		}
	}

	// Check Resources match (rule's Resources must be a subset of policy's Resource)
	if len(rule.Resources) > 0 {
		hasMatch := false
		for _, resource := range rule.Resources {
			if resource == policy.Resource || containsWildcard(policy.Resource) {
				hasMatch = true
				break
			}
		}
		if !hasMatch {
			return false
		}
	}

	// Check Verbs match (rule's Verbs must be a subset of policy's Verbs)
	if len(rule.Verbs) > 0 {
		for _, ruleVerb := range rule.Verbs {
			hasMatch := false
			for _, policyVerb := range policy.Verbs {
				if policyVerb == "*" || policyVerb == ruleVerb {
					hasMatch = true
					break
				}
			}
			if !hasMatch {
				return false
			}
		}
	}

	return true
}

// MatchRiskRules evaluates an RBAC policy against base and custom risk rules.
// It returns a slice of matching risk rules sorted by risk level (highest to lowest).
// If no custom rules match, it returns a slice containing only the matching base rule.
func MatchRiskRules(policy Policy) ([]RiskRule, error) {
	if policy.RoleType != "Role" && policy.RoleType != "ClusterRole" {
		return nil, fmt.Errorf("invalid role type: %s", policy.RoleType)
	}

	// Determine base risk level
	baseLevel := determineBaseRiskLevel(&policy)

	// Create base rule
	baseRule := RiskRule{
		Name:      fmt.Sprintf("Base Risk Level: %d", baseLevel),
		RiskLevel: baseLevel,
	}

	// Match against custom rules
	var matches []RiskRule
	for _, rule := range GetRiskRules() {
		if matchesCustomRule(&policy, &rule) {
			matches = append(matches, rule)
		}
	}

	// If no custom rules match, return only the base rule
	if len(matches) == 0 {
		return []RiskRule{baseRule}, nil
	}

	// Add base rule to matches
	matches = append(matches, baseRule)

	// Sort matches by risk level (highest to lowest)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].RiskLevel > matches[j].RiskLevel
	})

	return matches, nil
}
