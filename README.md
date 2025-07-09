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

## Releases

Official releases are available on the [GitHub Releases page](https://github.com/yourusername/rbac-scope/releases). Each release includes:
- Pre-compiled binaries for various operating systems and architectures (Linux, macOS, Windows).
- A multi-architecture Docker image.
- Release notes detailing changes.

To trigger a new release, maintainers will create and push a new Git tag in the format `vX.Y.Z` (e.g., `v1.0.0`). The release automation will then build and publish the artifacts.

## Container Image

A multi-architecture Docker image is available on Docker Hub. It supports `linux/amd64`, `linux/arm64`, and `linux/arm/v7` platforms.

You can pull the image using:
```bash
# For a specific version (recommended)
docker pull yourusername/rbac-scope:vX.Y.Z

# For the latest version
docker pull yourusername/rbac-scope:latest
```
Replace `yourusername` with the actual Docker Hub username/organization and `vX.Y.Z` with the desired version.

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
