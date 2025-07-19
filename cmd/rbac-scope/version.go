package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var versionOutput string

type VersionInfo struct {
	Version string `json:"version" yaml:"version"`
	Commit  string `json:"commit" yaml:"commit"`
	Date    string `json:"date" yaml:"date"`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of rbac-scope",
	Long:  `All software has versions. This is rbac-scope's`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := VersionInfo{
			Version: version,
			Commit:  commit,
			Date:    date,
		}

		switch versionOutput {
		case "json":
			jsonOutput, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				return fmt.Errorf("error formatting version to JSON: %w", err)
			}
			fmt.Println(string(jsonOutput))
		case "yaml":
			yamlOutput, err := yaml.Marshal(info)
			if err != nil {
				return fmt.Errorf("error formatting version to YAML: %w", err)
			}
			fmt.Println(string(yamlOutput))
		default:
			fmt.Printf("%s (built: %s commit: %s)\n", info.Version, info.Date, info.Commit)
		}

		return nil
	},
}

func init() {
	versionCmd.Flags().StringVarP(&versionOutput, "output", "o", "plain", "output format (plain, json, yaml)")
}
