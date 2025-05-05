# Escalato

Escalato is a Go-based tool for AWS IAM security auditing and management. It provides comprehensive visibility into IAM configurations and validates them against customizable security rules to identify potential vulnerabilities and misconfigurations.

## Technical Overview

### Architecture

Escalato is organized into several key packages:

- `cmd/`: Command-line interface implementation using Cobra
- `internal/aws/`: AWS API interaction and data collection
- `internal/models/`: Data structures for AWS resources and validation rules
- `internal/rules/`: Rules parsing and loading
- `internal/validator/`: Security rule validation engine

### Key Components

#### AWS Client

The AWS client (`internal/aws/client.go`) handles authentication and interaction with AWS API using the AWS SDK for Go v2. It supports:
- AWS profile selection
- Region configuration
- Session management
- Policy document caching

#### Rule Engine

The rule engine (`internal/validator/validator.go` and `internal/validator/policy_analyzer.go`) processes IAM configurations against rule definitions. It features:
- JSON policy document parsing and analysis
- Permission pattern matching
- Read vs. write action differentiation
- Support for multiple rule types
- Detailed violation reporting

#### Data Models

Key data models include:
- `Role`: IAM role with policies, trust relationships, and usage data
- `User`: IAM user with groups, policies, and access keys
- `Rule`: Security rule definition with conditions and severity
- `Condition`: Rule matching conditions for different resource types
- `Violation`: Security finding with details and context

## Prerequisites

- Go 1.23.3 or higher
- AWS SDK for Go v2
- AWS CLI configured or valid AWS credentials
- Required Go dependencies (see `go.mod`)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/escalato.git
cd escalato

# Install dependencies
go mod download

# Build the binary
go build -o escalato

# Optional: Install to system path
sudo mv escalato /usr/local/bin/
```

### Via Go Install

```bash
go install github.com/yourusername/escalato@latest
```

## Command Reference

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--profile, -p` | AWS profile to use | Default profile |
| `--region, -r` | AWS region | us-east-1 |

### User Commands

```bash
# List all IAM users
escalato users

# List users with access keys
escalato users --access-keys

# List users with policies
escalato users --policies

# List users with group membership
escalato users --groups

# Show all user details
escalato users --details
```

### Role Commands

```bash
# List all IAM roles
escalato roles

# Show role policies
escalato roles --policies

# Show trusted entities
escalato roles --trusted

# Show last activity
escalato roles --last-activity
```

### Validation Commands

```bash
# Run validation with default rules
escalato validate

# Use custom rules file
escalato validate --rules /path/to/rules.yml

# Export results to JSON
escalato validate --output-json results.json

# Enable diagnostic logging
escalato validate --diagnostics
```

## Rules Configuration Format

Escalato uses YAML for rule definitions. Each rule consists of:

```yaml
- name: "Rule Name"
  description: "Rule Description"
  severity: SEVERITY_LEVEL  # CRITICAL, HIGH, MEDIUM, LOW, INFO
  type: RULE_TYPE  # ROLE_TRUST_POLICY, ROLE_PERMISSIONS, USER_PERMISSIONS, USER_ACCESS_KEY
  condition:
    # Condition parameters vary by rule type
```

### Rule Types and Conditions

#### ROLE_TRUST_POLICY

For validating IAM role trust policies:

```yaml
type: ROLE_TRUST_POLICY
condition:
  service: "string or [array]"  # AWS service to check
  action: "string"             # IAM action to check
  principal_wildcard: bool     # Whether to check for wildcard principals
  aws_principal: bool          # Whether to check for AWS account principals
  require_conditions: bool     # Whether to require Condition element
  exclude_principals: [array]  # Principals to exclude from checks
```

#### ROLE_PERMISSIONS and USER_PERMISSIONS

For validating IAM permissions:

```yaml
type: ROLE_PERMISSIONS  # or USER_PERMISSIONS
condition:
  service: "string or [array]"  # AWS service(s) to check
  action: "string"             # IAM action to check
  managed_policy: "string"     # Specific managed policy to check
  exclude_patterns: [array]    # Policy names/patterns to exclude
```

#### USER_ACCESS_KEY

For validating IAM user access keys:

```yaml
type: USER_ACCESS_KEY
condition:
  key_age: integer            # Maximum allowed age in days
  key_status: "string"        # Status to check (Active, Inactive)
```

## Code Structure

```
escalato/
├── cmd/
│   ├── root.go           # Root command and global flags
│   ├── roles.go          # IAM roles commands
│   ├── users.go          # IAM users commands
│   └── validate.go       # Validation commands
├── example/
│   └── escalato-rules.yml # Example rules
├── internal/
│   ├── aws/
│   │   ├── client.go     # AWS client initialization
│   │   ├── display.go    # Output formatting
│   │   └── iam.go        # IAM API interactions
│   ├── models/
│   │   ├── role.go       # Role data structure
│   │   ├── rule.go       # Rule data structures
│   │   └── user.go       # User data structure
│   ├── rules/
│   │   └── loader.go     # YAML rule loading
│   └── validator/
│       ├── display.go    # Validation results display
│       ├── policy_analyzer.go # Policy document analysis
│       └── validator.go  # Main validation logic
├── go.mod
├── go.sum
└── main.go
```

## AWS Policy Analysis

The policy analyzer (`internal/validator/policy_analyzer.go`) implements advanced analysis:

1. **Policy Document Parsing**: Parses and normalizes IAM policy JSON
2. **Action Pattern Matching**: Detects exact and wildcard matches
3. **Read vs. Write Detection**: Differentiates read-only actions from write/admin actions
4. **Resource Wildcards**: Detects overly permissive resource specifications
5. **Statement Evaluation**: Processes Effect, Action, Resource, and Condition elements

### Read-Only Actions Detection

Escalato automatically identifies read-only actions by their prefixes:
- Get
- List
- Describe
- View
- Read
- Check
- Retrieve
- Monitor

### AWS Service Role Exclusion

The validator (`internal/validator/validator.go`) automatically excludes AWS managed service roles:
- Roles with paths containing `/aws-service-role/`
- Roles with names starting with `AWSServiceRole`

## Technical Details of Key Features

### Multi-Service Rules

The rule engine supports defining a single rule that applies to multiple AWS services:

```yaml
condition:
  service: ["lambda", "s3", "dynamodb", "rds", "ec2"]
  action: "*"
```

This is processed by the `getServicesFromCondition` function, which handles both string and array formats.

### Cross-Account Access Detection

Detects when a role can be assumed by another AWS account:

```go
// Excerpt from validateRoleTrustPolicy
if rule.Condition.AWSPrincipal {
    // Checks Principal.AWS field for cross-account ARNs
    // ...
}
```

### AssumeRole Condition Checking

Validates that `sts:AssumeRole` permissions have proper conditions:

```go
// Excerpt from validateRoleTrustPolicy
if rule.Condition.RequireConditions && rule.Condition.Action == "sts:AssumeRole" {
    if matchesAction && !hasConditions {
        // Report violation
    }
}
```

### Non-Read-Only Actions Detection

Analyzes policy for administrative actions:

```go
// Excerpt from analyzeStatements
if !isReadOnlyAction(action) {
    nonReadOnlyCount++
    nonReadOnlyActions = append(nonReadOnlyActions, action)
}

// If significant non-read-only actions found
if serviceMatches > 10 && nonReadOnlyCount >= 3 {
    // Report violation
}
```

## Error Handling

Escalato implements comprehensive error handling:

- AWS API errors are captured and reported with context
- YAML parsing errors include line numbers and context
- Policy document parsing errors provide detailed information
- Runtime errors include descriptive messages

## Extensions and Customization

### Adding New Rule Types

1. Add new constant in `internal/models/rule.go`:
```go
const (
    // Existing types
    NewRuleType RuleType = "NEW_RULE_TYPE"
)
```

2. Add validation logic in `internal/rules/loader.go`
3. Implement validation function in `internal/validator/validator.go`

### Custom Output Formats

Modify the `internal/validator/display.go` file to implement new output formats beyond the default console and JSON outputs.

## Performance Considerations

- Policies are cached to minimize AWS API calls
- Multiple AWS resources are processed concurrently
- Diagnostic logging can be enabled only when needed
- Policy document parsing is optimized for large documents

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Go best practices
2. Tests are included for new functionality
3. Documentation is updated
4. Pull requests include a description of changes

## License

[Add your license information here]