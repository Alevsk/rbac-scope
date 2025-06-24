package formatter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/policyevaluation"
	"github.com/alevsk/rbac-ops/internal/types"
	"github.com/jedib0t/go-pretty/v6/table"
)

// buildTables builds the tables for the given data
func buildTables(data types.Result) (table.Writer, table.Writer, table.Writer, table.Writer, error) {
	// Create Metadata table
	metadataTable := table.NewWriter()
	metadataTable.SetOutputMirror(nil)
	metadataTable.SetStyle(table.StyleLight)
	metadataTable.Style().Options.SeparateColumns = true

	// Set title for Metadata table
	metadataTable.SetTitle("METADATA")

	metadataTable.AppendHeader(table.Row{
		"KEY",
		"VALUE",
	})

	// Add row to table
	metadataTable.AppendRow(table.Row{
		"VERSION",
		data.Version,
	})

	metadataTable.AppendRow(table.Row{
		"NAME",
		data.Name,
	})

	metadataTable.AppendRow(table.Row{
		"SOURCE",
		data.Source,
	})

	metadataTable.AppendRow(table.Row{
		"TIMESTAMP",
		data.Timestamp,
	})

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
			return nil, nil, nil, nil, fmt.Errorf("invalid Identity data format")
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
		"TAGS",
	})

	// Extract RBAC data and create table entries
	if data.RBACData != nil {
		// Get the RBAC map that contains service account permissions
		rbacMap, ok := data.RBACData.Data["rbac"].(map[string]map[string]extractor.ServiceAccountRBAC)
		if !ok {
			return nil, nil, nil, nil, fmt.Errorf("invalid RBAC data format")
		}

		// Create an array to store rows
		var rows []table.Row

		// Iterate through each service account
		for saName, namespaceMap := range rbacMap {
			// Iterate through each namespace
			for namespace, saRBAC := range namespaceMap {
				// Iterate through each role
				for _, role := range saRBAC.Roles {
					// Iterate through permissions
					for apiGroup, resourceMap := range role.Permissions {
						for resource, resourceNameMap := range resourceMap {
							for resourceName, verbSet := range resourceNameMap {
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
									role.Type,
									role.Name,
									apiGroup,
									resource,
									strings.Join(verbs, ","),
								}

								riskRules, err := policyevaluation.MatchRiskRules(policyevaluation.Policy{
									Namespace:    namespace,
									RoleType:     role.Type,
									RoleName:     role.Name,
									APIGroup:     apiGroup,
									Resource:     resource,
									ResourceName: resourceName,
									Verbs:        verbs,
								})
								if err != nil {
									continue
								}

								if len(riskRules) > 0 {
									tags := policyevaluation.RiskTags{}
									// Get unique tags
									for _, rule := range riskRules {
										tags = append(tags, rule.Tags...)
									}
									tags = policyevaluation.UniqueRiskTags(tags)
									row = append(row, riskRules[0].RiskLevel, strings.Join(tags.StringSlice(3), ","))
								} else {
									row = append(row, "", "")
								}

								// Add row to array
								rows = append(rows, row)
							}
						}
					}
				}
			}
		}

		// Sort rows by risk level
		sort.Slice(rows, func(i, j int) bool {
			rowLeft := rows[i]
			rowRight := rows[j]
			return rowLeft[7].(policyevaluation.RiskLevel) > rowRight[7].(policyevaluation.RiskLevel)
		})

		// Append all rows to the table
		rbacTable.AppendRows(rows)
	}

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
			return nil, nil, nil, nil, fmt.Errorf("invalid Workload data format")
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

	return metadataTable, identityTable, rbacTable, workloadTable, nil
}
