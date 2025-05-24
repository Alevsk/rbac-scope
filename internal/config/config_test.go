package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigPrecedence(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := []byte(`
server:
  host: "127.0.0.1"
  port: 9090
  timeout: "1m"
  log_level: "debug"
database:
  host: "localhost"
  port: 5432
  name: "rbac_ops"
  user: "postgres"
  password: "secret"
  ssl_mode: "disable"
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Set environment variables (should override config file)
	os.Setenv("RBAC_OPS_SERVER_PORT", "9091")
	os.Setenv("RBAC_OPS_DATABASE_PASSWORD", "env-password")
	defer os.Unsetenv("RBAC_OPS_SERVER_PORT")
	defer os.Unsetenv("RBAC_OPS_DATABASE_PASSWORD")

	// Load the configuration
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Test config file values
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Server.Host)
	}

	// Test environment variable override
	if cfg.Server.Port != 9091 {
		t.Errorf("expected port 9091, got %d", cfg.Server.Port)
	}

	// Test duration parsing
	expectedTimeout := time.Minute
	if cfg.Server.Timeout != expectedTimeout {
		t.Errorf("expected timeout %v, got %v", expectedTimeout, cfg.Server.Timeout)
	}

	// Test database config
	if cfg.Database.Password != "env-password" {
		t.Errorf("expected database password env-password, got %s", cfg.Database.Password)
	}
	if cfg.Database.SSLMode != "disable" {
		t.Errorf("expected database ssl_mode disable, got %s", cfg.Database.SSLMode)
	}
}

func TestDefaultValues(t *testing.T) {
	// Load config without any file or env vars
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}

	// Test default values
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("expected log level info, got %s", cfg.Server.LogLevel)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("expected database host localhost, got %s", cfg.Database.Host)
	}
}

func TestConfigFileValidation(t *testing.T) {
	// Test non-existent config file
	_, err := Load("nonexistent.yml")
	if err == nil {
		t.Error("expected error for non-existent config file")
	}

	// Test invalid config file path
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid/config.yml")
	_, err = Load(configPath)
	if err == nil {
		t.Error("expected error for invalid config file path")
	}
}

func TestInvalidValues(t *testing.T) {
	// Create config with invalid values
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := []byte(`
server:
  port: "invalid"
  timeout: "invalid"
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Test invalid port
	os.Setenv("RBAC_OPS_SERVER_PORT", "invalid")
	defer os.Unsetenv("RBAC_OPS_SERVER_PORT")

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestInvalidDuration(t *testing.T) {
	// Create config with invalid duration
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := []byte(`
server:
  timeout: "invalid"
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}
