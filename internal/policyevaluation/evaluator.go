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

// matchesAPIGroups checks if policy's APIGroup matches any of rule's APIGroups
func matchesAPIGroups(policy *Policy, rule *RiskRule) bool {
	// Case 1: If rule has wildcard, policy must have wildcard
	if containsWildcardInSlice(rule.APIGroups) {
		if policy.APIGroup != "*" {
			fmt.Printf("Rule has wildcard APIGroup but policy doesn't\n")
			return false
		}
		fmt.Printf("Matched wildcard APIGroup\n")
		return true
	}

	// Case 2: Policy has wildcard, matches any rule's APIGroups
	if policy.APIGroup == "*" {
		fmt.Printf("Policy has wildcard APIGroup, matches any rule's APIGroups\n")
		return true
	}

	// Case 3: Check for core API group
	if policy.APIGroup == "" {
		// Policy is for core API group, check if rule matches
		for _, ruleGroup := range rule.APIGroups {
			if ruleGroup == "" {
				fmt.Printf("Matched core API group\n")
				return true
			}
		}
		fmt.Printf("Policy is for core API group but rule has different APIGroups\n")
		return false
	}

	// Case 4: Check if policy's APIGroup matches any of rule's APIGroups
	for _, ruleGroup := range rule.APIGroups {
		if ruleGroup == policy.APIGroup || (ruleGroup == "" && policy.APIGroup == "") {
			fmt.Printf("Rule's APIGroup %s matches policy's APIGroup\n", ruleGroup)
			return true
		}
	}

	fmt.Printf("No rule's APIGroup matches policy's APIGroup %s\n", policy.APIGroup)
	return false
}

func matchesResources(policy *Policy, rule *RiskRule) bool {
	// Case 1: If rule has wildcard, policy must have wildcard
	if containsWildcardInSlice(rule.Resources) {
		if policy.Resource != "*" {
			fmt.Printf("Rule has wildcard Resource but policy doesn't\n")
			return false
		}
		fmt.Printf("Matched wildcard Resource\n")
		return true
	}

	// Case 2: Policy has wildcard, matches any rule's Resources
	if policy.Resource == "*" {
		fmt.Printf("Policy has wildcard Resource, matches any rule's Resources\n")
		return true
	}

	// Case 3: No wildcards, check if rule's Resources are contained in policy's Resources
	for _, ruleResource := range rule.Resources {
		if ruleResource == policy.Resource {
			fmt.Printf("Rule's Resource %s matches policy's Resource %s\n", ruleResource, policy.Resource)
			return true
		}
	}
	fmt.Printf("No rule's Resource matches policy's Resource %s\n", policy.Resource)
	return false
}

func matchesVerbs(policy *Policy, rule *RiskRule) bool {
	// Case 1: If rule has wildcard, policy must have wildcard
	if containsWildcardInSlice(rule.Verbs) {
		for _, policyVerb := range policy.Verbs {
			if policyVerb == "*" {
				fmt.Printf("Matched wildcard Verbs\n")
				return true
			}
		}
		fmt.Printf("Rule has wildcard Verbs but policy doesn't\n")
		return false
	}

	// Case 2: Policy has wildcard, matches any rule's verbs
	for _, policyVerb := range policy.Verbs {
		if policyVerb == "*" {
			fmt.Printf("Policy has wildcard Verbs, matches any rule's verbs\n")
			return true
		}
	}

	// Case 3: No wildcards, check if rule's verbs are a subset of policy's verbs
	for _, ruleVerb := range rule.Verbs {
		var found bool
		for _, policyVerb := range policy.Verbs {
			if ruleVerb == policyVerb {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Rule's verb %s not found in policy's verbs\n", ruleVerb)
			return false
		}
	}
	fmt.Printf("Rule's verbs are a subset of policy's verbs\n")
	return true
}

// matchesCustomRule checks if a policy matches a custom risk rule
func matchesCustomRule(policy *Policy, rule *RiskRule) bool {
	// RoleType must match exactly, except for Role vs ClusterRole
	if policy.RoleType == "Role" && rule.RoleType == "ClusterRole" {
		// A Role cannot match a ClusterRole rule
		fmt.Printf("RoleType mismatch: rule=%s, policy=%s\n", rule.RoleType, policy.RoleType)
		return false
	}

	// Check all three conditions
	if !matchesAPIGroups(policy, rule) {
		return false
	}

	if !matchesResources(policy, rule) {
		return false
	}

	if !matchesVerbs(policy, rule) {
		return false
	}

	fmt.Printf("Rule %q matches!\n", rule.Name)
	return true
}

// MatchRiskRules evaluates an RBAC policy against base and custom risk rules.
// It first tries to match against custom rules, and always includes base risk level.
// Returns a slice of matching risk rules sorted by risk level (highest to lowest).
func MatchRiskRules(policy Policy) ([]RiskRule, error) {
	if policy.RoleType != "Role" && policy.RoleType != "ClusterRole" {
		return nil, fmt.Errorf("invalid role type: %s", policy.RoleType)
	}

	// Try to match against custom rules
	var matches []RiskRule
	for _, rule := range GetRiskRules() {
		if matchesCustomRule(&policy, &rule) {
			matches = append(matches, rule)
		}
	}

	// Get base risk level
	baseLevel := determineBaseRiskLevel(&policy)
	baseRule := RiskRule{
		Name:      fmt.Sprintf("Base Risk Level: %d", baseLevel),
		RiskLevel: baseLevel,
	}

	// If we found custom rule matches, sort them by risk level
	if len(matches) > 0 {
		// Sort matches by risk level (highest to lowest)
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].RiskLevel > matches[j].RiskLevel
		})

		// Return highest risk match and base risk level
		return []RiskRule{matches[0], baseRule}, nil
	}

	// No custom rules matched, return only base risk level
	return []RiskRule{baseRule}, nil
}
