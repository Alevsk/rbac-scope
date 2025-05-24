package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the RBAC-Ops API server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Starting RBAC-Ops API server on %s:%d...\n", cfg.Server.Host, cfg.Server.Port)
		// TODO: Implement API server
	},
}
