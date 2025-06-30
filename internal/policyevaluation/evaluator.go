package policyevaluation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/alevsk/rbac-scope/internal/logger"
)

// isResourceNamesPresent checks if policy.ResourceNames is present and not empty or "*"
func isResourceNamesPresent(policy *Policy) bool {
	return policy.ResourceName != "" && policy.ResourceName != "*"
}

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

// determineBaseRiskRule evaluates a policy against base risk rules
func determineBaseRiskRule(policy *Policy) RiskRule {
	// Check for Critical first (cluster-wide + wildcards everywhere)
	if isClusterScoped(policy) &&
		containsWildcard(policy.APIGroup) &&
		containsWildcard(policy.Resource) &&
		containsWildcardInSlice(policy.Verbs) {
		return BaseRiskRuleCritical
	}

	// Check for High (cluster-wide + some wildcards)
	if isClusterScoped(policy) &&
		(containsWildcard(policy.APIGroup) ||
			containsWildcard(policy.Resource) ||
			containsWildcardInSlice(policy.Verbs)) {
		return BaseRiskRuleHigh
	}

	// Check for Medium (namespaced + some wildcards)
	if !isClusterScoped(policy) &&
		(containsWildcard(policy.APIGroup) ||
			containsWildcard(policy.Resource) ||
			containsWildcardInSlice(policy.Verbs)) {
		return BaseRiskRuleMedium
	}

	// Default to Low (namespaced + no wildcards)
	return BaseRiskRuleLow
}

// matchesAPIGroups checks if policy's APIGroup matches any of rule's APIGroups
func matchesAPIGroups(policy *Policy, rule *RiskRule) bool {
	// Case 1: If rule has wildcard, policy must have wildcard
	if containsWildcardInSlice(rule.APIGroups) {
		if policy.APIGroup != "*" {
			logger.Debug().Msg("Rule has wildcard APIGroup but policy doesn't")
			return false
		}
		logger.Debug().Msg("Matched wildcard APIGroup")
		return true
	}

	// Case 2: Policy has wildcard, matches any rule's APIGroups
	if policy.APIGroup == "*" {
		logger.Debug().Msg("Policy has wildcard APIGroup, matches any rule's APIGroups")
		return true
	}

	// Case 3: Check for core API group
	if policy.APIGroup == "" {
		// Policy is for core API group, check if rule matches
		for _, ruleGroup := range rule.APIGroups {
			if ruleGroup == "" {
				logger.Debug().Msg("Matched core API group")
				return true
			}
		}
		logger.Debug().Msg("Policy is for core API group but rule has different APIGroups")
		return false
	}

	// Case 4: Check if policy's APIGroup matches any of rule's APIGroups
	for _, ruleGroup := range rule.APIGroups {
		if ruleGroup == policy.APIGroup || (ruleGroup == "" && policy.APIGroup == "") {
			logger.Debug().Msgf("Rule's APIGroup %s matches policy's APIGroup %s", ruleGroup, policy.APIGroup)
			return true
		}
	}

	logger.Debug().Msgf("No rule's APIGroup matches policy's APIGroup %s", policy.APIGroup)
	return false
}

func matchesResources(policy *Policy, rule *RiskRule) bool {
	// Case 1: If rule has wildcard, policy must have wildcard
	if containsWildcardInSlice(rule.Resources) {
		if policy.Resource != "*" {
			logger.Debug().Msg("Rule has wildcard Resource but policy doesn't")
			return false
		}
		logger.Debug().Msg("Matched wildcard Resource")
		return true
	}

	// Case 2: Policy has wildcard, matches any rule's Resources
	if policy.Resource == "*" {
		logger.Debug().Msg("Policy has wildcard Resource, matches any rule's Resources")
		return true
	}

	// Case 3: No wildcards, check if rule's Resources are contained in policy's Resources
	for _, ruleResource := range rule.Resources {
		if ruleResource == policy.Resource {
			logger.Debug().Msgf("Rule's Resource %s matches policy's Resource %s", ruleResource, policy.Resource)
			return true
		}
	}
	logger.Debug().Msgf("No rule's Resource matches policy's Resource %s", policy.Resource)
	return false
}

func matchesVerbs(policy *Policy, rule *RiskRule) bool {
	// Case 1: If rule has wildcard, policy must have wildcard
	if containsWildcardInSlice(rule.Verbs) {
		for _, policyVerb := range policy.Verbs {
			if policyVerb == "*" {
				logger.Debug().Msg("Matched wildcard Verbs")
				return true
			}
		}
		logger.Debug().Msg("Rule has wildcard Verbs but policy doesn't")
		return false
	}

	// Case 2: Policy has wildcard, matches any rule's verbs
	for _, policyVerb := range policy.Verbs {
		if policyVerb == "*" {
			logger.Debug().Msg("Policy has wildcard Verbs, matches any rule's verbs")
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
			logger.Debug().Msgf("Rule's verb %s not found in policy's verbs %v", ruleVerb, policy.Verbs)
			return false
		}
	}
	logger.Debug().Msg("Rule's verbs are a subset of policy's verbs")
	return true
}

// matchesCustomRule checks if a policy matches a custom risk rule
func matchesCustomRule(policy *Policy, rule *RiskRule) bool {
	// RoleType must match exactly, except for Role vs ClusterRole
	if policy.RoleType == "Role" && rule.RoleType == "ClusterRole" {
		// A Role cannot match a ClusterRole rule
		logger.Debug().Msgf("RoleType mismatch: rule=%s, policy=%s", rule.RoleType, policy.RoleType)
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

	logger.Debug().Msgf("Rule %q matches!", rule.Name)
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
		// Create a copy of the rule to avoid modifying the global rule set
		ruleCopy := rule
		if matchesCustomRule(&policy, &ruleCopy) {
			matches = append(matches, ruleCopy)
		}
	}

	// Get base risk level
	baseRule := determineBaseRiskRule(&policy)
	// If resource names are present, set risk level to low and add resource name restricted tag to base rule
	if isResourceNamesPresent(&policy) {
		baseRule.RiskLevel = RiskLevelLow
		baseRule.Tags = append(baseRule.Tags, ResourceNameRestricted)
		baseRule.ResourceName = policy.ResourceName
	}

	// If we found custom rule matches, sort them by risk level
	if len(matches) > 0 {

		// If resource names are present, set risk level to low and add resource name restricted tag to all matches
		if isResourceNamesPresent(&policy) {
			for i := range matches {
				tags := matches[i].Tags
				matches[i].RiskLevel = RiskLevelLow // Risk level is considered low if resource names are present because blast radius is reduced to a single resource
				matches[i].Tags = append(tags, ResourceNameRestricted)
				matches[i].ResourceName = policy.ResourceName
			}
		}

		// Sort matches by risk level (highest to lowest)
		// This might be less critical if all are RiskLevelLow due to ResourceNames
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].RiskLevel > matches[j].RiskLevel
		})

		// Return matches and base risk level
		// Ensure baseRule is added only if it's not effectively superseded by a resourceName-restricted custom match
		// or if no custom matches occurred.
		// If resourceNamesRestricted is true and matches exist, baseRule might be redundant if it's also low.
		// However, the original logic always adds baseRule, so we maintain that for now.
		return append(matches, baseRule), nil
	}

	// No custom rules matched, return only base risk level
	return []RiskRule{baseRule}, nil
}
