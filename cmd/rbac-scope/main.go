package main

import (
	"fmt"
	"os"

	"github.com/alevsk/rbac-scope/internal/config"
	"github.com/alevsk/rbac-scope/internal/logger"
	"github.com/spf13/cobra"
)

var (
	configPath string
	debug      bool
)

var cfg = &config.Config{}

var rootCmd = &cobra.Command{
	Use:   "rbac-scope",
	Short: "RBAC-Scope - A Kubernetes RBAC policy analyzer",
	Long: `RBAC-Scope is a tool for analyzing RBAC policies used by Kubernetes Operators,
helping identify permissions, potential risks, and abuse scenarios.`,
	SilenceErrors: true, // We'll handle error printing ourselves
	SilenceUsage:  true, // We'll handle usage printing ourselves
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		// Load configuration from file or environment variable
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("error loading configuration: %w", err)
		}

		// flags override config due to highest precedence
		if debug {
			cfg.Debug = true
		}

		// Initialize logger
		logger.Init(cfg)

		// Print configuration source
		if configPath != "" || os.Getenv(config.RbacOpsConfigPathEnvVar) != "" {
			logger.Debug().Msgf("Using config file: %s", configPath)
		} else {
			logger.Debug().Msg("Using default configuration")
		}

		return nil
	},
}

func init() {
	// Add global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config file (default: config.yml in current directory)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable verbose logging and additional debug information")

	// Add commands
	rootCmd.AddCommand(serveCmd)

	// Add cobra completion command
	rootCmd.AddCommand(completionCmd)

	// Add analyze command to root command
	rootCmd.AddCommand(analyzeCmd)

	// Add version command to root command
	rootCmd.AddCommand(versionCmd)
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
