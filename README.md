# RBAC-Scope

A curated database of RBAC policies used by popular Kubernetes Operators, with security annotations highlighting their permissions, potential risks, and abuse scenarios.

## Features

- Collection and analysis of RBAC policies from popular Kubernetes Operators
- Security risk assessment and annotation
- Permission abuse scenario documentation
- REST API for policy querying
- CLI tool for policy management

## Quick Start

### Prerequisites

- Go 1.21.5 or later
- Docker (for containerized deployment)
- Access to a Kubernetes cluster (for testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/rbac-scope.git
cd rbac-scope

# Install dependencies
make install-deps

# Build the project
make build

# Run tests
make test
```

### Configuration

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` with your configuration values

### Usage

```bash
# Run the CLI tool
./bin/rbac-scope --help

# Start the API server
./bin/rbac-scope serve
```

## Development

### Building

```bash
# Format code
make fmt

# Run linter
make lint

# Run tests with coverage
make cover

# Build Docker image
make docker
```

### Project Structure

```
.
├── cmd/            # Command line interface
├── internal/       # Private application code
├── pkg/           # Public API packages
├── api/           # API documentation
└── docs/          # Additional documentation
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Security

For security concerns, please refer to our [Security Policy](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
