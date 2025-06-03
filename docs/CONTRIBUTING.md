---
label: Contributing to KubeBrowse
icon:  book
order: 800
---

# Contributing to KubeBrowse

Thank you for your interest in contributing to GUAC! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Contributing to KubeBrowse](#contributing-to-kubebrowse)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [Getting Started](#getting-started)
    - [Development Environment Setup](#development-environment-setup)
    - [Troubleshooting Common Issues](#troubleshooting-common-issues)
    - [Project Structure](#project-structure)
  - [Development Workflow](#development-workflow)
    - [Branching Strategy](#branching-strategy)
    - [Commit Guidelines](#commit-guidelines)
    - [Pre-commit Hooks](#pre-commit-hooks)
  - [Pull Requests](#pull-requests)
    - [PR Process](#pr-process)
    - [PR Requirements](#pr-requirements)
  - [Coding Standards](#coding-standards)
    - [Go Guidelines](#go-guidelines)
    - [Testing](#testing)
    - [Documentation](#documentation)
  - [Release Process](#release-process)

## Code of Conduct

We are committed to fostering a welcoming community. Please read and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions.

## Getting Started

### Development Environment Setup

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/browsersec/KubeBrowse.git
   cd KubeBrowse
   ```

2. **Set up the development environment**

   ```bash
   # Install dependencies and Git hooks
   make setup
   ```

3. **Run the application**

   ```bash
   make run
   ```

4. **Access the application**

   - Open a browser and navigate to `http://localhost:4567/connect`

### Troubleshooting Common Issues

#### Go Version Mismatch

If you encounter errors like `compile: version "go1.24.0" does not match go tool version "go1.24.3"`, follow these steps:

1. **Check your Go version**

   ```bash
   go version
   ```

2. **Clean the Go module cache**

   ```bash
   go clean -modcache
   ```

3. **Clean the Go build cache**

   ```bash
   go clean -cache
   ```

4. **Reset the build system**

   ```bash
   rm -rf $GOPATH/pkg/mod/cache/build
   ```

5. **Install or update to a consistent Go version**
   
   Using Go's official installation:
   ```bash
   # Download the latest version
   wget https://go.dev/dl/go1.24.3.linux-amd64.tar.gz
   
   # Remove old installation (if needed)
   sudo rm -rf /usr/local/go
   
   # Install the new version
   sudo tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz
   ```
   
   Or using a version manager like `asdf`:
   ```bash
   asdf install golang 1.24.3
   asdf global golang 1.24.3
   ```

6. **Check your environment variables**
   
   Ensure your PATH and GOROOT are set correctly:
   ```bash
   # Add to your shell profile (.bashrc, .zshrc, etc.)
   export GOROOT=/usr/local/go
   export PATH=$GOROOT/bin:$PATH
   ```

7. **Regenerate the Go modules**

   ```bash
   go mod tidy
   ```

### Project Structure

- `/cmd/guac/` - Main application entry point
- `/utils/` - Utility functions
- `/certs/` - Certificate files for TLS
- `/.githooks/` - Git hooks for development



## Development Workflow

### Branching Strategy

- `main` - Stable branch containing the latest release
- `dev` - Development branch for integrating features
- Feature branches should be created from `dev` and named using the format: `feature/short-description` or `fix/issue-description`

### Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:

```
<type>(<scope>): <description>

<body>

<footer>
```

Types include:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix bugs nor add features
- `test`: Adding or modifying tests
- `chore`: Changes to the build process or auxiliary tools

Example:
```
feat(api): add endpoint for user authentication

- Implement JWT token generation
- Add middleware for token validation

Fixes #123
```

### Pre-commit Hooks

This project uses [Lefthook](https://github.com/evilmartians/lefthook) for managing Git hooks to ensure code quality. The pre-commit hook checks:

- Code formatting
- Static analysis
- Linting
- Tests
- Potential secrets

Install the hooks with:
```bash
make hooks
```

You can manually run the pre-commit checks:
```bash
# Check only staged files
make lint

# Check all files in the repository
make lint-all
```

If Lefthook is not found, you'll be prompted to install it. Lefthook hooks are automatically installed when you run `make setup`.

## Pull Requests

### PR Process

1. Create a new branch from `dev`
2. Implement your changes
3. Ensure tests pass and code meets quality standards
4. Push your branch and create a pull request against `dev`
5. Address any feedback from reviewers

### PR Requirements

- PRs must have a clear description of changes
- All tests must pass
- Code must be properly formatted
- Documentation must be updated if necessary
- Changes should be covered by tests

## Coding Standards

### Go Guidelines

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use the standard Go formatting (`gofmt`)
- Write idiomatic Go code
- Keep functions small and focused
- Add comments for exported functions, types, and packages

### Testing

- Write tests for all new features and bug fixes
- Aim for high test coverage, especially for critical paths
- Use table-driven tests when appropriate
- Run tests with `make test`

### Documentation

- Document all exported functions, types, and packages
- Update the README.md if adding new features or changing existing functionality
- Add examples for complex features

## Release Process

1. Create a release branch from `dev`
2. Update version information
3. Run comprehensive tests
4. Merge to `main` once approved
5. Tag the release with the version number
6. Update documentation with release notes

Thank you for contributing to GUAC!
*