# Escalato

Escalato is a flexible, extensible Go-based tool for AWS IAM security auditing and management. It provides comprehensive visibility into IAM configurations and validates them against customizable security rules to identify potential vulnerabilities and misconfigurations.

## Key Features

- **Rule-Based Validation**: Define security rules in YAML with a flexible, expression-based syntax
- **Plugin Architecture**: Easily extend with new rule types without changing the core code
- **Confidence Levels**: Every security finding includes a confidence assessment
- **IAM Resource Management**: View and manage roles, users, policies, and permissions
- **Detailed Reporting**: Comprehensive violation reporting with context and evidence
- **JSON Export**: Export validation results for integration with other tools

## Technical Overview

### Architecture

Escalato is organized with a clean, modular architecture:

- **Resource Model**: Generic interfaces for AWS resources that decouples validation from specific resource types
- **Rule Engine**: Flexible, expression-based rule evaluation engine
- **Validator Registry**: Plugin-based system for registering condition validators
- **Policy Analyzer**: Sophisticated IAM policy document analysis

### New Components

- **Expression Evaluator**: Evaluates complex logical expressions against resource properties
- **Evaluation Context**: Collects and shares information during rule evaluation
- **Condition Validators**: Pluggable validators for different types of security checks

## Using Escalato

### Installation

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

### Command Reference

#### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--profile, -p` | AWS profile to use | Default profile |
| `--region, -r` | AWS region | us-east-1 |

#### User & Role Commands

```bash
# List all IAM users
escalato users

# List all IAM roles
escalato roles

# Show detailed information with various flags
escalato users --details
escalato roles --trusted --policies --last-activity
```

#### Validation Command

```bash
# Run validation with default rules
escalato validate

# Use custom rules file
escalato validate --rules /path/to/rules.yml

# Filter by confidence or severity
escalato validate --min-confidence HIGH --min-severity MEDIUM

# Export results to JSON
escalato validate --output-json results.json

# Enable diagnostic logging
escalato validate --diagnostics
```

## Defining Security Rules

Escalato uses a flexible YAML format for defining rules. Each rule consists of:

```yaml
- id: rule_id
  name: "Rule Name"
  description: "Rule Description"
  severity: SEVERITY_LEVEL  # CRITICAL, HIGH, MEDIUM, LOW, INFO
  resource_type: ResourceType  # Role, User
  conditions:
    - type: CONDITION_TYPE
      # Condition-specific parameters
  confidence_rules:
    - level: CONFIDENCE_LEVEL  # HIGH, MEDIUM, LOW
      when: "expression"
    - level: LOW
      default: true
```

### Condition Types

The new rule engine supports multiple condition types:

#### POLICY_DOCUMENT

Validates IAM policy documents:

```yaml
type: POLICY_DOCUMENT
document_path: "TrustPolicy"  # or "Policies[0].Document"
match:
  statement_effect: "Allow"
  action: "s3:*"
  service: "s3"
  has_condition: false
  principal:
    has_wildcard: true
```

#### RESOURCE_PROPERTY

Checks resource properties:

```yaml
type: RESOURCE_PROPERTY
property_path: "Path"
value: "/aws-service-role/"
```

#### PATTERN_MATCH

Matches string patterns:

```yaml
type: PATTERN_MATCH
property_path: "RoleName"
pattern: "admin"
options:
  type: "contains"  # or "prefix", "suffix", "exact"
```

#### AGE_CONDITION

Checks time-based conditions:

```yaml
type: AGE_CONDITION
property_path: "AccessKeys[0].CreateDate"
threshold: 90  # days
```

#### Logical Operators

Combine conditions with logical operators:

```yaml
type: AND  # or OR, NOT
conditions:
  - type: RESOURCE_PROPERTY
    # ...
  - type: POLICY_DOCUMENT
    # ...
```

### Confidence Rules

Define how confident the tool is in its findings:

```yaml
confidence_rules:
  - level: HIGH
    when: "has_wildcard_principal && !has_conditions"
  - level: MEDIUM
    when: "non_read_only_count > 5"
  - level: LOW
    default: true
```

## Examples

Here are some examples of common security rules:

### Wildcard in AssumeRole Trust Policy

```yaml
- id: wildcard_assume_role
  name: "Wildcard in AssumeRole Trust Policy"
  description: "Role has a trusted policy with sts:AssumeRole and wildcard principal"
  severity: CRITICAL
  resource_type: Role
  conditions:
    - type: POLICY_DOCUMENT
      document_path: "TrustPolicy"
      match:
        statement_effect: "Allow"
        action: "sts:AssumeRole"
        principal:
          has_wildcard: true
  confidence_rules:
    - level: HIGH
      when: "has_wildcard_principal && !has_conditions"
    - level: MEDIUM
      when: "has_wildcard_principal && has_conditions"
    - level: LOW
      default: true
```

### Outdated Access Keys

```yaml
- id: outdated_access_key
  name: "Outdated Access Key"
  description: "User has access key older than 180 days"
  severity: HIGH
  resource_type: User
  conditions:
    - type: AGE_CONDITION
      property_path: "AccessKeys[0].CreateDate"
      threshold: 180
  confidence_rules:
    - level: HIGH
      when: "ageInDays > 365"
    - level: MEDIUM
      when: "ageInDays > 270"
    - level: LOW
      default: true
```

## Extending Escalato

### Adding New Resource Types

1. Create a new struct that implements the `models.Resource` interface
2. Update AWS client to fetch and populate the new resource type
3. Register it in the validator

### Adding New Condition Types

1. Add a new constant in `models.ConditionType`
2. Implement a new validator that implements the `validator.ConditionValidator` interface
3. Register it in the validator registry

### Creating Custom Expressions

Use the expression evaluator to create custom expressions for confidence rules:

```go
// Register a custom function
evaluator.RegisterFunction("isHighRiskService", func(args ...interface{}) (interface{}, error) {
    if len(args) != 1 {
        return nil, errors.New("isHighRiskService requires 1 argument")
    }
    
    service, ok := args[0].(string)
    if !ok {
        return nil, errors.New("argument must be a string")
    }
    
    highRiskServices := []string{"iam", "lambda", "ec2", "cloudformation", "s3"}
    for _, s := range highRiskServices {
        if service == s {
            return true, nil
        }
    }
    
    return false, nil
})
```

## Performance Considerations

- Resource properties are accessed using reflection only when needed
- Evaluation context caches intermediate results during rule evaluation
- Policy documents are parsed only once
- Multiple AWS resources are processed concurrently
- Diagnostic logging can be enabled only when needed

