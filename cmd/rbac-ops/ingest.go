package main

import (
	"fmt"

	"github.com/alevsk/rbac-ops/internal/ingestor"
	"github.com/spf13/cobra"
)

var (
	ingestOpts = &ingestor.Options{}
	source     string
)

var ingestCmd = &cobra.Command{
	Use:   "ingest [source]",
	Short: "Ingest RBAC policies from various sources",
	Long: `Ingest RBAC policies from various sources such as local YAML files, remote URLs,
or directories containing Kubernetes manifests.

Examples:
  # Ingest from a local YAML file
  rbac-ops ingest operator.yaml

  # Ingest from a remote URL
  rbac-ops ingest https://raw.githubusercontent.com/org/repo/main/deploy/rbac.yaml

  # Ingest from a directory
  rbac-ops ingest ./deploy/operators/`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source = args[0]

		ing := ingestor.New(ingestOpts)
		result, err := ing.Ingest(cmd.Context(), source)
		if err != nil {
			return fmt.Errorf("ingestion failed: %w", err)
		}

		if !result.Success {
			return fmt.Errorf("ingestion failed: %v", result.Error)
		}

		fmt.Print(result.OutputFormatted)
		return nil
	},
}

func init() {

	// Add flags specific to ingest command
	flags := ingestCmd.Flags()
	flags.IntVar(&ingestOpts.MaxConcurrency, "concurrency", 4,
		"maximum number of concurrent ingestion operations")
	flags.BoolVar(&ingestOpts.FollowSymlinks, "follow-symlinks", false,
		"follow symbolic links during directory traversal")
	flags.BoolVar(&ingestOpts.ValidateYAML, "validate-yaml", true,
		"enable strict YAML validation during ingestion")
	flags.StringVarP(&ingestOpts.OutputFormat, "output", "o", "table", "output format (table, json, yaml)")
}
