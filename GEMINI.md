# RBAC-Ops Development Guide


## Bash commands

- `make all`: Run all tasks (clean, install deps, fmt, lint, test, build)
- `make build`: Build the project binary
- `make clean`: Clean build artifacts and coverage files
- `make test`: Run all tests with coverage
- `make cover`: Generate HTML coverage report
- `make fmt`: Format Go code
- `make lint`: Run golangci-lint for static code analysis
- `make docker`: Build Docker image and tag as latest
- `make install-deps`: Install project dependencies and tools

## Code style

- Follow standard Go code conventions and idioms
- Use Go modules for dependency management
- Run `make fmt` before committing to ensure consistent code formatting
- Ensure all code passes `make lint` checks
- Write comprehensive tests for new functionality
- Document public APIs and complex logic

## Workflow

- Always run `make install-deps` after pulling new changes
- Format code with `make fmt` before committing
- Run `make lint` to catch potential issues early
- Write tests alongside new code changes
- Use `make test` to run the full test suite with coverage
- For faster development, run specific tests, here are some examples:
  - Test a specific package: `go test -v ./internal/policyevaluation`
  - Test a specific test function: `go test -timeout 30s -run ^TestMatchRiskRules$ github.com/alevsk/rbac-scope/internal/policyevaluation`
  - Test a specific test case: `go test -timeout 30s -run ^TestMatchRiskRules/Resource_with_specific_resourceName_restriction$ github.com/alevsk/rbac-scope/internal/policyevaluation`
- Check coverage reports with `make cover` for areas needing testing
- Build and test Docker images locally with `make docker` before pushing
- Use semantic versioning for releases (VERSION variable in Makefile)
