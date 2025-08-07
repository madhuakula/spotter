---
title: CLI Reference
description: Complete command-line interface reference for Spotter
---

Spotter provides a comprehensive command-line interface for scanning Kubernetes resources, managing security rules, and configuring the tool. This reference covers all available commands, flags, and options.

## Global Flags

These flags are available for all commands:

```bash
Global Flags:
      --config string        config file (default is $HOME/.spotter.yaml)
      --kubeconfig string    path to kubeconfig file
      --log-format string    log format (text, json) (default "text")
      --log-level string     log level (trace, debug, info, warn, error, fatal, panic) (default "info")
      --no-color             disable colored output
      --output string        output format (table, json, yaml, sarif) (default "table")
      --output-file string   output file path
      --rules-path strings   paths to security rules directories or files
      --timeout string       timeout for operations (default "5m")
  -v, --verbose              verbose output
```

## Main Commands

### `spotter scan`

Scan Kubernetes resources for security issues.

```bash
spotter scan [command] [flags]
```

**Subcommands:**
- `cluster` - Scan a live Kubernetes cluster
- `manifests` - Scan Kubernetes manifest files
- `helm` - Scan Helm charts

#### `spotter scan cluster`

Scan a live Kubernetes cluster for security misconfigurations.

```bash
spotter scan cluster [flags]
```

**Examples:**

```bash
# Scan entire cluster
spotter scan cluster

# Scan specific namespace
spotter scan cluster --namespace production

# Scan multiple namespaces
spotter scan cluster --namespace "prod,staging"

# Scan specific resource types
spotter scan cluster --resource-types "pods,deployments,services"

# Use specific kubeconfig
spotter scan cluster --kubeconfig /path/to/kubeconfig

# Use specific context
spotter scan cluster --context production-cluster

# Filter by severity
spotter scan cluster --min-severity high

# Output to file
spotter scan cluster --output json --output-file results.json
```

**Flags:**

```bash
Flags:
      --categories strings           rule categories to include
      --context string               kubernetes context to use
      --exclude-namespaces strings   namespaces to exclude from scanning
      --exclude-rules strings        specific rule IDs to exclude
      --exclude-system-namespaces    exclude system namespaces (kube-system, kube-public, etc.)
  -h, --help                         help for cluster
      --include-cluster-resources    include cluster-scoped resources (default true)
      --include-rules strings        specific rule IDs to include
      --max-violations int           maximum number of violations before stopping scan (0 = no limit)
      --min-severity string          minimum severity level to include (low, medium, high, critical)
  -n, --namespace strings            namespaces to scan (default: all non-system namespaces)
      --parallelism int              number of parallel workers for scanning and rule evaluation (default 4)
      --quiet                        suppress non-error output
      --resource-types strings       specific resource types to scan (format: group/version/kind, e.g., apps/v1/Deployment)
      --summary-only                 show only summary statistics
```

#### `spotter scan manifests`

Scan Kubernetes manifest files for security issues.

```bash
spotter scan manifests [path...] [flags]
```

**Examples:**

```bash
# Scan single file
spotter scan manifests deployment.yaml

# Scan multiple files
spotter scan manifests pod.yaml service.yaml

# Scan directory
spotter scan manifests ./k8s-manifests/

# Scan recursively
spotter scan manifests ./k8s-manifests/ --recursive

# Scan with glob patterns
spotter scan manifests "./manifests/**/*.yaml"
```

**Flags:**

```bash
Flags:
      --categories strings          rule categories to include
      --exclude-rules strings       specific rule IDs to exclude
      --exclude-system-namespaces   exclude system namespaces (kube-system, kube-public, etc.)
      --file-extensions strings     file extensions to scan (default [.yaml,.yml,.json])
      --follow-symlinks             follow symbolic links when scanning directories
  -h, --help                        help for manifests
      --include-cluster-resources   include cluster-scoped resources (default true)
      --include-paths strings       paths to include in scanning
      --include-rules strings       specific rule IDs to include
      --max-violations int          maximum number of violations before stopping scan (0 = no limit)
      --min-severity string         minimum severity level to include (low, medium, high, critical)
      --parallelism int             number of parallel workers for scanning and rule evaluation (default 4)
      --quiet                       suppress non-error output
      --recursive                   recursively scan directories (default true)
      --summary-only                show only summary statistics
```

#### `spotter scan helm`

Scan Helm charts for security issues.

```bash
spotter scan helm [chart] [flags]
```

**Examples:**

```bash
# Scan local chart
spotter scan helm ./my-chart

# Scan with custom values
spotter scan helm ./my-chart --values values-prod.yaml

# Scan installed release
spotter scan helm --release my-app --namespace production

# Scan with set values
spotter scan helm ./my-chart --set image.tag=v1.2.3,replicas=3
```

**Flags:**

```bash
--values strings           Values files (comma-separated)
--set strings              Set values (key=value,key=value)
--set-string strings       Set string values
--set-file strings         Set values from files
--release string           Scan installed Helm release
--namespace string         Namespace for Helm operations
--repo string              Helm repository URL
--version string           Chart version
--dry-run                  Render templates without installation
```

### `spotter rules`

Manage security rules.

```bash
spotter rules [command] [flags]
```

**Subcommands:**
- `list` - List available security rules
- `info` - Show detailed information about a rule
- `validate` - Validate custom rules
- `export` - Export rules in different formats
- `generate` - Generate a new security rule template

#### `spotter rules list`

List available security rules.

```bash
spotter rules list [flags]
```

**Examples:**

```bash
# List all rules
spotter rules list

# List rules by category
spotter rules list --category "Workload Security"

# List rules by severity
spotter rules list --severity critical

# Output as JSON
spotter rules list --output json
```

**Flags:**

```bash
Flags:
      --builtin-only       show only built-in rules
      --category strings   filter by rule categories
      --custom-only        show only custom rules
  -h, --help               help for list
      --search string      search rules by name or description
      --severity strings   filter by severity levels (low, medium, high, critical)
      --show-description   show rule descriptions in output
      --show-source        show rule source (built-in or custom) in output
```

#### `spotter rules show`

Show detailed information about a specific rule.

```bash
spotter rules info [rule-id] [flags]
```

**Examples:**

```bash
# Show specific rule
spotter rules info SPOTTER-WORKLOAD-SECURITY-100

# Show with CEL query
spotter rules info SPOTTER-WORKLOAD-SECURITY-100 --show-cel
```

**Flags:**

```bash
Flags:
  -h, --help       help for info
      --show-cel   show CEL expression in output
```

#### `spotter rules validate`

Validate custom security rules.

```bash
spotter rules validate [path...] [flags]
```

**Examples:**

```bash
# Validate single rule file
spotter rules validate custom-rule.yaml

# Validate directory of rules
spotter rules validate ./custom-rules/

# Validate with strict mode
spotter rules validate ./custom-rules/ --strict
```

**Flags:**

```bash
Flags:
      --check-duplicates          check for duplicate rule IDs (default true)
      --file-extensions strings   file extensions to validate (default [.yaml,.yml])
  -h, --help                      help for validate
      --recursive                 recursively validate directories (default true)
      --strict                    treat warnings as errors
      --test-cases                validate test cases using *_test.yaml files in same directory as rules
      --validate-cel              validate CEL expressions (default true)
```

#### `spotter rules export`

Export security rules to files.

```bash
spotter rules export [flags]
```

**Examples:**

```bash
# Export all rules
spotter rules export --output-dir ./exported-rules

# Export specific category
spotter rules export --category "Workload Security" --output-dir ./workload-rules

# Export as single file
spotter rules export --output-file all-rules.yaml
```

**Flags:**

```bash
Flags:
      --builtin-only       export only built-in rules
      --category strings   export rules by category
      --custom-only        export only custom rules
      --format string      export format (json, yaml, sarif, csv) (default "json")
  -h, --help               help for export
      --include-metadata   include rule metadata in export (default true)
      --severity strings   export rules by severity
```

### `spotter version`

Show version information.

```bash
spotter version [flags]
```

**Examples:**

```bash
# Show version
spotter version

# Show detailed version info
spotter version --detailed

# Output as JSON
spotter version --output json
```

**Flags:**

```bash
Flags:
  -h, --help            help for version
  -o, --output string   Output format (text, json, yaml) (default "text")
  -s, --short           Display short version information
```

## Common Flags

These flags are available for scan commands:

### Output Flags

```bash
--output string            Output format (table,json,yaml,sarif) (default: table)
--output-file string       Output file path (default: stdout)
--no-color                Disable colored output
--quiet                   Suppress non-essential output
--verbose                 Enable verbose output
```

### Filtering Flags

```bash
--min-severity string      Minimum severity level (info,low,medium,high,critical)
--max-severity string      Maximum severity level
--categories strings       Filter by categories (comma-separated)
--include-rules strings    Include specific rules (comma-separated)
--exclude-rules strings    Exclude specific rules (comma-separated)
--include-passed          Include passed checks in output
```

## Getting Help

Use the `--help` flag with any command to get detailed usage information:

```bash
# General help
spotter --help

# Command-specific help
spotter scan --help
spotter scan cluster --help
spotter rules list --help
```

For more examples and advanced usage patterns, check the [Quick Start Guide](/quick-start/).
