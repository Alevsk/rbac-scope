# Configuration Guide

RBAC-Ops can be configured using multiple methods, listed here in order of precedence (highest to lowest):

1. Command-line flags
2. Environment variables
3. Configuration file
4. Default values

## Configuration File

By default, RBAC-Ops looks for a `config.yml` file in the current directory. You can specify a different configuration file using the `--config` flag or the `RBAC_OPS_CONFIG_PATH` environment variable.

Example `config.yml`:

```yaml
debug: false
server:
  host: "0.0.0.0"
  port: 8080
  timeout: "30s"
  log_level: "info"
database:
  host: "localhost"
  port: 5432
  name: "rbac_ops"
  user: "postgres"
  password: ""
  ssl_mode: "disable"
```

## Environment Variables

All configuration options can be set via environment variables using the prefix `RBAC_OPS_` followed by the configuration key in uppercase, with dots replaced by underscores.

Examples:

- `RBAC_OPS_SERVER_HOST=localhost`
- `RBAC_OPS_SERVER_PORT=1337`
- `RBAC_OPS_DATABASE_PASSWORD=secret`
- `RBAC_OPS_DEBUG=true`

## Configuration Options

### Global Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `debug` | `RBAC_OPS_DEBUG` | `false` | Enable verbose logging and debug information |

### Server Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `server.host` | `RBAC_OPS_SERVER_HOST` | `0.0.0.0` | Server host address |
| `server.port` | `RBAC_OPS_SERVER_PORT` | `8080` | Server port |
| `server.timeout` | `RBAC_OPS_SERVER_TIMEOUT` | `30s` | Server timeout duration |
| `server.log_level` | `RBAC_OPS_SERVER_LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |

### Database Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `database.host` | `RBAC_OPS_DATABASE_HOST` | `localhost` | Database host |
| `database.port` | `RBAC_OPS_DATABASE_PORT` | `5432` | Database port |
| `database.name` | `RBAC_OPS_DATABASE_NAME` | `rbac_ops` | Database name |
| `database.user` | `RBAC_OPS_DATABASE_USER` | `postgres` | Database user |
| `database.password` | `RBAC_OPS_DATABASE_PASSWORD` | `""` | Database password |
| `database.ssl_mode` | `RBAC_OPS_DATABASE_SSL_MODE` | `disable` | Database SSL mode |

## Command-line Flags

Command-line flags take precedence over all other configuration methods. The available flags correspond to the configuration options above:

```bash
rbac-ops [command] [flags]

Flags:
  --config string              Config file path
  --debug                      Enable debug mode
  --server.host string        Server host (default "0.0.0.0")
  --server.port int          Server port (default 8080)
  --server.timeout duration  Server timeout (default 30s)
  --server.log-level string  Log level (default "info")
  --database.host string       Database host (default "localhost")
  --database.port int          Database port (default 5432)
  --database.name string       Database name (default "rbac_ops")
  --database.user string       Database user (default "postgres")
  --database.password string   Database password
  --database.ssl-mode string   Database SSL mode (default "disable")
```

## Configuration Precedence Example

Here's an example of how different configuration methods interact:

1. In `config.yml`:

```yaml
server:
  port: 8080
```

1. Environment variable set:

```bash
export RBAC_OPS_SERVER_PORT=9090
```

1. Command-line flag:

```bash
rbac-ops serve --port 1337
```

In this case, the server will run on port 1337 because command-line flags have the highest precedence.
