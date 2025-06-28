package main

import (
	"fmt"

	"github.com/alevsk/rbac-ops/internal/ingestor"
	"github.com/spf13/cobra"
)

var (
	analyzeOpts = &ingestor.Options{}
	source      string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [source]",
	Short: "Analyze RBAC policies from various sources",
	Long: `Analyze RBAC policies from various sources such as local YAML files, remote URLs,
or directories containing Kubernetes manifests.

Examples:
  # Analyze from a local YAML file
  rbac-ops analyze operator.yaml

  # Analyze from a remote URL
  rbac-ops analyze https://raw.githubusercontent.com/org/repo/main/deploy/rbac.yaml

  # Analyze from a directory
  rbac-ops analyze ./deploy/operators/

  # Analyze from a helm chart
  rbac-ops analyze ./deploy/operators/ -f values.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source = args[0]

		ing := ingestor.New(analyzeOpts)
		result, err := ing.Ingest(cmd.Context(), source)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if !result.Success {
			return fmt.Errorf("analysis failed: %v", result.Error)
		}

		fmt.Print(result.OutputFormatted)
		return nil
	},
}

func init() {

	// Add flags specific to analyze command
	flags := analyzeCmd.Flags()
	flags.IntVar(&analyzeOpts.MaxConcurrency, "concurrency", 4,
		"maximum number of concurrent analysis operations")
	flags.BoolVar(&analyzeOpts.FollowSymlinks, "follow-symlinks", false,
		"follow symbolic links during directory traversal")
	flags.BoolVar(&analyzeOpts.ValidateYAML, "validate-yaml", true,
		"enable strict YAML validation during analysis")
	flags.StringVarP(&analyzeOpts.OutputFormat, "output", "o", "table", "output format (table, json, yaml, markdown)")
	flags.BoolVar(&analyzeOpts.IncludeMetadata, "include-metadata", true,
		"include metadata in the output")
	flags.StringVarP(&analyzeOpts.Values, "values", "f", "", "path to a values.yaml file used for rendering a helm chart")
}
