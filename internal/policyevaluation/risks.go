package policyevaluation

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed risks.yaml
var risksYAMLBytes []byte

// riskRules contains the loaded risk rules from the YAML file.
// It is unexported to prevent direct modification from other packages.
var riskRules []RiskRule

// validateRiskRule ensures a risk rule has all required fields.
func validateRiskRule(rule RiskRule) error {
	if rule.Name == "" {
		return fmt.Errorf("risk rule missing name")
	}
	if rule.RoleType != "Role" && rule.RoleType != "ClusterRole" {
		return fmt.Errorf("invalid role type %q in rule %q", rule.RoleType, rule.Name)
	}
	if rule.RiskLevel < RiskLevelLow || rule.RiskLevel > RiskLevelCritical {
		return fmt.Errorf("invalid risk level %d in rule %q", rule.RiskLevel, rule.Name)
	}
	return nil
}

// loadRiskRules loads and validates the risk rules from the embedded YAML.
// It returns an error if the YAML is invalid or if any rule is invalid.
func loadRiskRules() error {
	var rules []RiskRule
	if err := yaml.Unmarshal(risksYAMLBytes, &rules); err != nil {
		return fmt.Errorf("failed to parse risk rules YAML: %v", err)
	}

	// Validate all rules
	for _, rule := range rules {
		if err := validateRiskRule(rule); err != nil {
			return fmt.Errorf("invalid risk rule: %v", err)
		}
	}

	riskRules = rules
	return nil
}

// GetRiskRules returns a copy of the loaded risk rules.
// This prevents external packages from modifying the rules directly.
func GetRiskRules() []RiskRule {
	rulesCopy := make([]RiskRule, len(riskRules))
	copy(rulesCopy, riskRules)
	return rulesCopy
}

func init() {
	if err := loadRiskRules(); err != nil {
		// In production, you might want to handle this differently
		// depending on your application's needs
		panic(fmt.Sprintf("failed to load risk rules: %v", err))
	}
}
