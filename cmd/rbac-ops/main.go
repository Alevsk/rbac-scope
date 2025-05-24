package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "rbac-ops",
	Short: "RBAC-Ops - A Kubernetes RBAC policy analyzer",
	Long: `RBAC-Ops is a tool for analyzing RBAC policies used by Kubernetes Operators,
helping identify permissions, potential risks, and abuse scenarios.`,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the RBAC-Ops API server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting RBAC-Ops API server...")
		// TODO: Implement API server
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
