package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Server flags
	serverHost     string
	serverPort     int
	serverTimeout  string
	serverLogLevel string
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the RBAC-Scope API server",
	PreRun: func(cmd *cobra.Command, args []string) {
		// Override config values with flags if provided
		if cmd.Flags().Changed("host") {
			cfg.Server.Host = serverHost
		}
		if cmd.Flags().Changed("port") {
			cfg.Server.Port = serverPort
		}
		if cmd.Flags().Changed("timeout") {
			if duration, err := time.ParseDuration(serverTimeout); err == nil {
				cfg.Server.Timeout = duration
			}
		}
		if cmd.Flags().Changed("log-level") {
			cfg.Server.LogLevel = serverLogLevel
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Starting RBAC-Scope API server on %s:%d...\n", cfg.Server.Host, cfg.Server.Port)
		fmt.Printf("Log level: %s, Timeout: %v\n", cfg.Server.LogLevel, cfg.Server.Timeout)
		// TODO: Implement API server
	},
}

func init() {
	// Server flags
	serveCmd.Flags().StringVarP(&serverHost, "host", "H", "", "Server host (default: 0.0.0.0)")
	serveCmd.Flags().IntVarP(&serverPort, "port", "p", 0, "Server port (default: 8080)")
	serveCmd.Flags().StringVarP(&serverTimeout, "timeout", "t", "", "Server timeout (e.g., 30s, 1m)")
	serveCmd.Flags().StringVarP(&serverLogLevel, "log-level", "l", "", "Log level (debug, info, warn, error)")

	// Bind flags to viper
	if err := viper.BindPFlag("server.host", serveCmd.Flags().Lookup("host")); err != nil {
		panic(fmt.Sprintf("failed to bind flag: %v", err))
	}
	if err := viper.BindPFlag("server.port", serveCmd.Flags().Lookup("port")); err != nil {
		panic(fmt.Sprintf("failed to bind flag: %v", err))
	}
	if err := viper.BindPFlag("server.timeout", serveCmd.Flags().Lookup("timeout")); err != nil {
		panic(fmt.Sprintf("failed to bind flag: %v", err))
	}
	if err := viper.BindPFlag("server.log_level", serveCmd.Flags().Lookup("log-level")); err != nil {
		panic(fmt.Sprintf("failed to bind flag: %v", err))
	}
}
