---
title: Contributing Guide
description: Learn how to contribute to Spotter development
---

We welcome contributions to Spotter! This guide will help you get started with contributing code, documentation, security rules, and more.

## Getting Started

### Prerequisites

- **Go**: Required for building Spotter
- **Git**: For version control
- **Make**: For build automation
- **Docker**: For containerized development (optional)
- **Kubernetes cluster**: For testing (kind, minikube, or cloud cluster)

### Development Setup

1. **Fork and Clone**

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/spotter.git
cd spotter

# Add upstream remote
git remote add upstream https://github.com/madhuakula/spotter.git
```

2. **Install Dependencies**

```bash
# Install Go dependencies
go mod download
```

3. **Build and Test**

```bash
# Build the project
make build

# Run tests
make test

# Run linting
make lint
```

## Development Workflow

### 1. Create a Feature Branch

```bash
# Update main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-number-description
```

### 2. Make Changes

```bash
# Make your changes
# Add tests for new functionality
# Update documentation if needed

# Run tests frequently
make test

# Check code quality
make lint
```

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add new security rule for privileged containers"

# Follow conventional commit format:
# feat: new feature
# fix: bug fix
# docs: documentation changes
# style: formatting changes
# refactor: code refactoring
# test: adding tests
# chore: maintenance tasks
```

### 4. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
# Fill out the PR template
# Link related issues
```

## Community Guidelines

### Code of Conduct

We follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/). Please be respectful and inclusive in all interactions.

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions

### Getting Help

1. **Check Documentation**: Start with the docs
2. **Search Issues**: Look for existing discussions
3. **Ask Questions**: Use GitHub Discussions

### Recognition

We recognize contributors through:

- **Contributors file**: Listed in CONTRIBUTORS.md
- **Release notes**: Mentioned in changelogs
- **Social media**: Highlighted on Twitter/LinkedIn

Thank you for contributing to Spotter! Your contributions help make Kubernetes security accessible to everyone.
