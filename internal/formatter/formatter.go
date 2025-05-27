package formatter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/types"
	"github.com/jedib0t/go-pretty/v6/table"
	"gopkg.in/yaml.v3"
)

// RBACTableEntry represents a single row in the RBAC permissions table
type RBACTableEntry struct {
	Identity  string
	Namespace string
	RoleType  string
	RoleName  string
	APIGroup  string
	Resource  string
	Verbs     string
}

// Formatter defines the interface for formatting data
type Formatter interface {
	Format(data types.Result) (string, error)
}

// Type represents the type of formatter
type Type string

const (
	// TypeJSON formats data as JSON
	TypeJSON Type = "json"
	// TypeYAML formats data as YAML
	TypeYAML Type = "yaml"
	// TypeTable formats data as a table
	TypeTable Type = "table"
)

// JSON implements JSON formatting
type JSON struct{}

// YAML implements YAML formatting
type YAML struct{}

// Table implements table formatting
type Table struct{}

// Format formats data as JSON
func (j *JSON) Format(data types.Result) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error formatting as JSON: %w", err)
	}
	return string(bytes), nil
}

// Format formats data as YAML
func (y *YAML) Format(data types.Result) (string, error) {
	bytes, err := yaml.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("error formatting as YAML: %w", err)
	}
	return string(bytes), nil
}

// Format formats data as a table using go-pretty/v6/table
func (t *Table) Format(data types.Result) (string, error) {
	// Create Identity table
	identityTable := table.NewWriter()
	identityTable.SetOutputMirror(nil)
	identityTable.SetStyle(table.StyleLight)
	identityTable.Style().Options.SeparateColumns = true

	// Set title for Identity table
	identityTable.SetTitle("SERVICE ACCOUNT IDENTITIES")

	// Set the headers for Identity table
	identityTable.AppendHeader(table.Row{
		"IDENTITY",
		"NAMESPACE",
		"AUTOMOUNT TOKEN",
		"SECRETS",
		"IMAGE PULL SECRETS",
	})

	// Extract Identity data and create table entries
	if data.IdentityData != nil {
		// Get the Identity map that contains service account identities
		identityMap, ok := data.IdentityData.Data["identities"].(map[string]map[string]extractor.Identity)
		if !ok {
			return "", fmt.Errorf("invalid Identity data format")
		}

		// Iterate through each service account
		for saName, namespaceMap := range identityMap {
			// Iterate through each namespace
			for namespace, identity := range namespaceMap {
				// Add row to table
				identityTable.AppendRow(table.Row{
					saName,
					namespace,
					identity.AutomountToken,
					strings.Join(identity.Secrets, ","),
					strings.Join(identity.ImagePullSecrets, ","),
				})
			}
		}
	}

	// Sort Identity table by service account name and namespace
	identityTable.SortBy([]table.SortBy{
		{Name: "IDENTITY", Mode: table.Asc},
		{Name: "NAMESPACE", Mode: table.Asc},
	})

	// Create RBAC table
	rbacTable := table.NewWriter()
	rbacTable.SetOutputMirror(nil) // Don't write to stdout directly
	rbacTable.SetStyle(table.StyleLight)
	rbacTable.Style().Options.SeparateColumns = true

	// Set title for RBAC table
	rbacTable.SetTitle("SERVICE ACCOUNT BINDINGS")

	// Set the headers for RBAC table
	rbacTable.AppendHeader(table.Row{
		"IDENTITY",
		"NAMESPACE",
		"ROLE TYPE",
		"ROLE NAME",
		"API GROUP",
		"RESOURCE",
		"VERBS",
		"RISK",
	})

	// Extract RBAC data and create table entries
	if data.RBACData != nil {
		// Get the RBAC map that contains service account permissions
		rbacMap, ok := data.RBACData.Data["rbac"].(map[string]map[string]extractor.ServiceAccountRBAC)
		if !ok {
			return "", fmt.Errorf("invalid RBAC data format")
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

							row := table.Row{
								saName,
								namespace,
								role.Type, // This will be either "Role" or "ClusterRole"
								role.Name,
								apiGroup,
								resource,
								strings.Join(verbs, ","),
							}

							riskRule := MatchRiskRule(row)
							if riskRule != nil {
								row = append(row, riskRule.RiskLevel.String())
							} else {
								row = append(row, "")
							}
							// Add row to table
							rbacTable.AppendRow(row)
						}
					}
				}
			}
		}
	}

	// Sort RBAC table by service account name and namespace
	rbacTable.SortBy([]table.SortBy{
		{Name: "IDENTITY", Mode: table.Asc},
		{Name: "NAMESPACE", Mode: table.Asc},
	})

	// Create Workload table
	workloadTable := table.NewWriter()
	workloadTable.SetOutputMirror(nil)
	workloadTable.SetStyle(table.StyleLight)
	workloadTable.Style().Options.SeparateColumns = true

	// Set title for Workload table
	workloadTable.SetTitle("SERVICE ACCOUNT WORKLOADS")

	// Set the headers for Workload table
	workloadTable.AppendHeader(table.Row{
		"IDENTITY",
		"NAMESPACE",
		"WORKLOAD TYPE",
		"WORKLOAD NAME",
		"CONTAINER",
		"IMAGE",
	})

	// Extract Workload data and create table entries
	if data.WorkloadData != nil {
		// Get the Workload map that contains service account workloads
		workloadMap, ok := data.WorkloadData.Data["workloads"].(map[string]map[string][]extractor.Workload)
		if !ok {
			return "", fmt.Errorf("invalid Workload data format")
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
						workloadTable.AppendRow(table.Row{
							saName,
							namespace,
							workload.Type,
							workload.Name,
							container.Name,
							container.Image,
						})
					}
				}
			}
		}
	}

	// Sort Workload table by service account name and namespace
	workloadTable.SortBy([]table.SortBy{
		{Name: "IDENTITY", Mode: table.Asc},
		{Name: "NAMESPACE", Mode: table.Asc},
	})

	// Combine all tables with newline separators
	return identityTable.Render() + "\n\n" + rbacTable.Render() + "\n\n" + workloadTable.Render() + "\n", nil
}

// ParseType converts a string to a Type
func ParseType(s string) (Type, error) {
	switch Type(s) {
	case TypeJSON, TypeYAML, TypeTable:
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
	default:
		return nil, fmt.Errorf("unknown formatter type: %s", t)
	}
}
