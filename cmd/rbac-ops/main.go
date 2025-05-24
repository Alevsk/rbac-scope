package main

import (
	"fmt"
	"os"

	"github.com/alevsk/rbac-ops/internal/config"
	"github.com/spf13/cobra"
)

var (
	configPath string
	cfg        *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "rbac-ops",
	Short: "RBAC-Ops - A Kubernetes RBAC policy analyzer",
	Long: `RBAC-Ops is a tool for analyzing RBAC policies used by Kubernetes Operators,
helping identify permissions, potential risks, and abuse scenarios.`,
	SilenceErrors: true, // We'll handle error printing ourselves
	SilenceUsage:  true, // We'll handle usage printing ourselves
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("error loading configuration: %w", err)
		}

		// Print configuration source
		if configPath != "" || os.Getenv(config.RbacOpsConfigPathEnvVar) != "" {
			fmt.Printf("Using config file: %s\n", configPath)
		} else {
			fmt.Println("Using default configuration")
		}

		return nil
	},
}

func init() {
	// Add global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config file (default: config.yml in current directory)")

	// Add commands
	rootCmd.AddCommand(serveCmd)

	// Add cobra completion command
	rootCmd.AddCommand(completionCmd)
}

func main() {
	// Custom error handling to show usage before error
	if err := rootCmd.Execute(); err != nil {
		// Get the most recent command
		cmd := rootCmd
		if c, err2 := rootCmd.ExecuteC(); err2 == nil {
			cmd = c
		}
		// Show usage first
		fmt.Println(cmd.UsageString())
		// Then show the error
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
