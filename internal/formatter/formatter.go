package formatter

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/types"
	"gopkg.in/yaml.v3"
)

// Formatter defines the interface for formatting data
type Formatter interface {
	Format(data types.Result) (string, error)
}

// Format formats data as JSON
func (j *JSON) Format(rawData types.Result) (string, error) {
	data, err := PrepareData(rawData)
	if err != nil {
		return "", fmt.Errorf("error preparing data: %w", err)
	}
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error formatting as JSON: %w", err)
	}
	return string(bytes), nil
}

// Format formats data as YAML
func (y *YAML) Format(rawData types.Result) (string, error) {
	data, err := PrepareData(rawData)
	if err != nil {
		return "", fmt.Errorf("error preparing data: %w", err)
	}
	bytes, err := yaml.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("error formatting as YAML: %w", err)
	}
	return string(bytes), nil
}

// Format formats data as a table using go-pretty/v6/table
func (t *Table) Format(data types.Result) (string, error) {
	identityTable, rbacTable, workloadTable, err := buildTables(data)
	if err != nil {
		return "", err
	}
	// Combine all tables with newline separators
	return identityTable.Render() + "\n\n" + rbacTable.Render() + "\n\n" + workloadTable.Render() + "\n", nil
}

// Format formats data as a markdown using go-pretty/v6/table
func (t *Markdown) Format(data types.Result) (string, error) {
	identityTable, rbacTable, workloadTable, err := buildTables(data)
	if err != nil {
		return "", err
	}
	// Combine all tables with newline separators
	return identityTable.RenderMarkdown() + "\n\n" + rbacTable.RenderMarkdown() + "\n\n" + workloadTable.RenderMarkdown() + "\n", nil
}

// ParseType converts a string to a Type
func ParseType(s string) (Type, error) {
	switch Type(s) {
	case TypeJSON, TypeYAML, TypeTable, TypeMarkdown:
		return Type(s), nil
	default:
		return "", fmt.Errorf("unknown formatter type: %s", s)
	}
}

// NewFormatter creates a new formatter of the specified type
func NewFormatter(t Type) (Formatter, error) {
	switch t {
	case TypeJSON:
		return &JSON{}, nil
	case TypeYAML:
		return &YAML{}, nil
	case TypeTable:
		return &Table{}, nil
	case TypeMarkdown:
		return &Markdown{}, nil
	default:
		return nil, fmt.Errorf("unknown formatter type: %s", t)
	}
}

// PrepareData parses the data removing unnecessary information
func PrepareData(data types.Result) (ParsedData, error) {

	var parsedData ParsedData
	parsedData.IdentityData = make([]SAIdentityEntry, 0)
	parsedData.RBACData = make([]SARoleBindingEntry, 0)
	parsedData.WorkloadData = make([]SAWorkloadEntry, 0)

	// Extract Identity data and create table entries
	if data.IdentityData != nil {
		// Get the Identity map that contains service account identities
		identityMap, ok := data.IdentityData.Data["identities"].(map[string]map[string]extractor.Identity)
		if !ok {
			return parsedData, fmt.Errorf("invalid Identity data format")
		}

		// Iterate through each service account
		for saName, namespaceMap := range identityMap {
			// Iterate through each namespace
			for namespace, identity := range namespaceMap {
				// Add row to table
				parsedData.IdentityData = append(parsedData.IdentityData, SAIdentityEntry{
					saName,
					namespace,
					identity.AutomountToken,
					identity.Secrets,
					identity.ImagePullSecrets,
				})
			}
		}
	}

	// Extract RBAC data and create table entries
	if data.RBACData != nil {
		// Get the RBAC map that contains service account permissions
		rbacMap, ok := data.RBACData.Data["rbac"].(map[string]map[string]extractor.ServiceAccountRBAC)
		if !ok {
			return parsedData, fmt.Errorf("invalid RBAC data format")
		}

		// Iterate through each service account
		for saName, namespaceMap := range rbacMap {
			// Iterate through each namespace
			for namespace, saRBAC := range namespaceMap {
				// Iterate through each role
				for _, role := range saRBAC.Roles {
					// Iterate through permissions
					for apiGroup, resourceMap := range role.Permissions {
						for resource, verbSet := range resourceMap {
							// Convert verbs set to slice
							verbs := make([]string, 0, len(verbSet))
							for verb := range verbSet {
								verbs = append(verbs, verb)
							}

							// Sort verbs for consistent output
							sort.Strings(verbs)

							entry := SARoleBindingEntry{
								saName,
								namespace,
								role.Type,
								role.Name,
								apiGroup,
								resource,
								verbs,
								"",
							}

							riskRule := MatchRiskRule(entry)
							if riskRule != nil {
								entry.RiskLevel = riskRule.RiskLevel.String()
							}

							parsedData.RBACData = append(parsedData.RBACData, entry)

						}
					}
				}
			}
		}
	}

	// Extract Workload data and create table entries
	if data.WorkloadData != nil {
		// Get the Workload map that contains service account workloads
		workloadMap, ok := data.WorkloadData.Data["workloads"].(map[string]map[string][]extractor.Workload)
		if !ok {
			return parsedData, fmt.Errorf("invalid Workload data format")
		}

		// Iterate through each service account
		for saName, namespaceMap := range workloadMap {
			// Iterate through each namespace
			for namespace, workloads := range namespaceMap {
				// Iterate through each workload
				for _, workload := range workloads {
					// Iterate through containers
					for _, container := range workload.Containers {
						// Add row to table
						parsedData.WorkloadData = append(parsedData.WorkloadData, SAWorkloadEntry{
							saName,
							namespace,
							string(workload.Type),
							workload.Name,
							container.Name,
							container.Image,
						})
					}
				}
			}
		}
	}

	return parsedData, nil
}
