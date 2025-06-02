package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	RbacOpsConfigPathEnvVar = "RBAC_OPS_CONFIG_PATH" // Environment variable for config path
)

// Config holds all configuration for the application
type Config struct {
	// Debug enables verbose logging and additional debug information
	Debug bool `mapstructure:"debug"`
	// Server configuration
	Server struct {
		Host     string        `mapstructure:"host"`
		Port     int           `mapstructure:"port"`
		Timeout  time.Duration `mapstructure:"timeout"`
		LogLevel string        `mapstructure:"log_level"`
	} `mapstructure:"server"`

	// Database configuration
	Database struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Name     string `mapstructure:"name"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		SSLMode  string `mapstructure:"ssl_mode"`
	} `mapstructure:"database"`
}

// Load initializes and returns the configuration from all sources:
// 1. Command-line flags (highest priority)
// 2. Environment variables (prefixed with RBAC_OPS_)
// 3. Configuration file (lowest priority)
func Load(configPath string) (*Config, error) {
	// Check for environment variable config path if not explicitly provided
	if configPath == "" {
		if envPath := os.Getenv(RbacOpsConfigPathEnvVar); envPath != "" {
			if _, err := os.Stat(envPath); os.IsNotExist(err) {
				return nil, fmt.Errorf("config file specified in %s not found: %s", RbacOpsConfigPathEnvVar, envPath)
			}
			configPath = envPath
		}
	} else {
		// Verify explicitly provided config file exists
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", configPath)
		}
	}
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Read config file if specified
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config.yml in the current directory
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
	}

	// Read environment variables
	v.SetEnvPrefix("RBAC_OPS")
	v.AutomaticEnv()
	// Replace dots with underscores in env vars
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		} else if configPath != "" {
			// Only error if config file was explicitly specified
			return nil, fmt.Errorf("specified config file not found: %s", configPath)
		}
		// If no config file was specified, we'll use defaults
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

// setDefaults sets default values for all configuration options
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.timeout", "30s")
	v.SetDefault("server.log_level", "info")

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "rbac_ops")
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.ssl_mode", "disable")

}
