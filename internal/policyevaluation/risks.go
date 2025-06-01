package policyevaluation

var RiskRules = []RiskRule{
	{
		Name:        "Read secrets cluster-wide",
		Description: "Grants access to read all secrets across all namespaces in the cluster. This is extremely critical as secrets often contain sensitive credentials, API keys, tokens, and other confidential data, leading to widespread data exposure and potential full cluster compromise.",
		Category:    "Information Disclosure",
		RiskLevel:   RiskLevelCritical,
		APIGroups:   []string{},
		RoleType:    "ClusterRole",
		Resources:   []string{"secrets"},
		Verbs:       []string{"get", "list", "watch"},
		Tags:        RiskTags{ClusterWideSecretAccess, CredentialAccess, DataExposure, InformationDisclosure},
	},
}
