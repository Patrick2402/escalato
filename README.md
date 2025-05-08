# Escalato - AWS IAM Security Auditing Tool

```
,------.                     ,--.          ,--.          
|  .---' ,---.  ,---. ,--,--.|  | ,--,--.,-'  '-. ,---.  
|  `--, (  .-' | .--'' ,-.  ||  |' ,-.  |'-.  .-'| .-. | 
|  `---..-'  `)\ `--.\ '-'  ||  |\ '-'  |  |  |  ' '-' ' 
`------'`----'  `---' `--`--'`--' `--`--'  `--'   `---'  
```

**Escalato** is a powerful, flexible tool for auditing AWS IAM security configurations. It evaluates IAM roles and users against a customizable set of security rules to identify potential vulnerabilities and enforce security best practices.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Commands](#basic-commands)
  - [Validation](#validation)
  - [Command Options](#command-options)
- [Rule Configuration](#rule-configuration)
  - [Rule Structure](#rule-structure)
  - [Condition Types](#condition-types)
  - [Global Exclusions](#global-exclusions)
  - [Confidence Levels](#confidence-levels)
- [Examples](#examples)
- [Advanced Features](#advanced-features)
  - [Regular Expressions](#regular-expressions)
  - [AWS Wildcard Patterns](#aws-wildcard-patterns)
- [Technical Architecture](#technical-architecture)
- [Extending Escalato](#extending-escalato)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Rule-Based Validation**: Define security rules in YAML with a flexible, expression-based syntax
- **Plugin Architecture**: Easily extend with new rule types without changing the core code
- **Confidence Levels**: Every security finding includes a confidence assessment
- **IAM Resource Management**: View and manage roles, users, policies, and permissions
- **Detailed Reporting**: Comprehensive violation reporting with context and evidence
- **JSON Export**: Export validation results for integration with other tools
- **Global Exclusions**: Define roles and users to be excluded from all validations
- **AWS-Aware**: Intelligent handling of AWS managed roles
- **Regular Expressions**: Advanced pattern matching in rules
- **AWS Wildcard Support**: Proper interpretation of AWS wildcard patterns in IAM policies

## Installation

### Prerequisites

- Go 1.18 or higher
- AWS credentials configured (via environment variables, AWS profile, or IAM role)

### Building from Source

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

## Usage

### Basic Commands

Escalato provides several commands to interact with AWS IAM resources:

```bash
# List all IAM users
escalato users

# List all IAM roles
escalato roles

# Show detailed information about users
escalato users --details

# Show roles with their trusted policies and attached policies
escalato roles --trusted --policies

# Show last activity information
escalato roles --last-activity
```

### Validation

The core functionality of Escalato is validating IAM resources against security rules:

```bash
# Run validation with default rules
escalato validate

# Use custom rules file
escalato validate --rules custom-rules.yml

# Filter by confidence or severity
escalato validate --min-confidence HIGH --min-severity MEDIUM

# Export results to JSON
escalato validate --output-json results.json

# Enable diagnostic logging
escalato validate --diagnostics
```

### Command Options

#### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--profile`, `-p` | AWS profile to use | Default profile |
| `--region`, `-r` | AWS region | us-east-1 |

#### User & Role Commands

| Flag | Description |
|------|-------------|
| `--details` | Show detailed information (users) |
| `--access-keys` | Show access keys information (users) |
| `--policies` | Show attached and inline policies |
| `--groups` | Show group memberships (users) |
| `--trusted` | Show trusted entities (roles) |
| `--last-activity` | Show last activity information |

#### Validation Command

| Flag | Description | Default |
|------|-------------|---------|
| `--rules` | Path to rules YAML file | escalato-rules.yml |
| `--output-json` | Export results to JSON file | |
| `--diagnostics` | Enable diagnostic output | false |
| `--min-confidence` | Minimum confidence level (HIGH, MEDIUM, LOW) | |
| `--min-severity` | Minimum severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO) | |
| `--skip-aws-roles` | Skip AWS managed roles during validation | true |

## Rule Configuration

Escalato uses a YAML file to define both security rules and global configurations.

### Rule Structure

Each rule consists of the following components:

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

Escalato supports multiple condition types to define flexible security rules:

#### POLICY_DOCUMENT

Evaluates IAM policy documents:

```yaml
type: POLICY_DOCUMENT
document_path: "TrustPolicy"  # or "Policies[0].Document"
match:
  statement_effect: "Allow"
  action: "s3:*"
  action_regex: "s3:(Delete.*|Put.*)"  # New feature: regex for actions
  service: "s3"
  has_condition: false
  resource: "*"
  resource_regex: "arn:aws:s3:::.*-prod-.*"  # New feature: regex for resources
  principal:
    has_wildcard: true
```

#### ALL_POLICIES

Checks all policies attached to a role or user:

```yaml
type: ALL_POLICIES
match:
  statement_effect: "Allow"
  action: "iam:*"
  action_regex: "iam:(Create|Delete|Update).*"  # New feature: regex for actions
  resource: "*"
  resource_regex: "arn:aws:.*:.*:role/.*admin.*"  # New feature: regex for resources
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
  type: "contains"  # Options: "contains", "prefix", "suffix", "exact", "regex" (new)
```

Using the new regex option:

```yaml
type: PATTERN_MATCH
property_path: "TrustPolicy"
pattern: "(lambda|ec2|s3)\\.amazonaws\\.com"
options:
  type: "regex"  # New feature: regex pattern matching
```

#### AGE_CONDITION

Checks time-based conditions:

```yaml
type: AGE_CONDITION
property_path: "AccessKeys[0].CreateDate"
threshold: 90  # days
```

#### UNUSED_PERMISSIONS

Identifies unused permissions:

```yaml
type: UNUSED_PERMISSIONS
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

### Global Exclusions

Define global exclusions at the top level of your rules file:

```yaml
# Global exclusion lists
excluded_roles:
  - AWSReservedSSO_AdministratorAccess
  - emergency-access-role
  - break-glass-role

excluded_users:
  - admin
  - service-account

# Rules follow...
rules:
  - id: first_rule
    # ...
```

### Confidence Levels

Define how confident the tool is in its findings:

```yaml
confidence_rules:
  - level: HIGH
    when: "has_global_wildcard"
  - level: MEDIUM
    when: "has_leading_or_trailing_wildcard"
  - level: LOW
    when: "has_wildcard_resource"
  - level: LOW
    default: true
```

## Examples

Here are some examples of common security rules:

### S3 Wildcard Access

```yaml
- id: s3_wildcard_access
  name: "S3 Wildcard Access"
  description: "Role has wildcard access to S3 buckets"
  severity: HIGH
  resource_type: Role
  conditions:
    - type: ALL_POLICIES
      match:
        statement_effect: "Allow"
        action: "s3:*"
        resource: "*"
  confidence_rules:
    - level: HIGH
      when: "has_global_wildcard"
    - level: MEDIUM
      when: "has_wildcard_resource"
    - level: LOW
      default: true
```

### AssumeRole With Wildcards

```yaml
- id: sts_assumeRole_wildcards
  name: "AssumeRole With Wildcards"
  description: "Role allows sts:AssumeRole with wildcard resources"
  severity: HIGH
  resource_type: Role
  conditions:
    - type: ALL_POLICIES
      match:
        statement_effect: "Allow"
        action: "sts:AssumeRole"
  confidence_rules:
    - level: HIGH
      when: "has_global_wildcard"
    - level: MEDIUM
      when: "has_leading_or_trailing_wildcard"
    - level: LOW
      when: "has_wildcard_resource"
    - level: LOW
      default: true
```

### Unused Role Permissions

```yaml
- id: unused_role_permissions
  name: "Unused Role Permissions"
  description: "Role has permissions that haven't been used in the last 90 days"
  severity: MEDIUM
  resource_type: Role
  conditions:
    - type: UNUSED_PERMISSIONS
      threshold: 90  # days
  confidence_rules:
    - level: HIGH
      when: "days_inactive > 180"
    - level: MEDIUM
      when: "days_inactive > 90"
    - level: LOW
      default: true
```

## Advanced Features

### Regular Expressions

Escalato supports advanced pattern matching using regular expressions in various condition types:

#### Administrative Role Naming Pattern Detection

```yaml
- id: admin_role_naming
  name: "Administrative Role Naming Pattern"
  description: "Role name matches administrative naming pattern"
  severity: HIGH
  resource_type: Role
  conditions:
    - type: PATTERN_MATCH
      property_path: "RoleName"
      pattern: "^(admin|root|superuser|sysadmin).*$"
      options:
        type: "regex"
  confidence_rules:
    - level: HIGH
      default: true
```

#### Sensitive AWS Service Actions

```yaml
- id: sensitive_s3_actions
  name: "Sensitive S3 Actions"
  description: "Role has permissions to perform sensitive S3 operations"
  severity: HIGH
  resource_type: Role
  conditions:
    - type: ALL_POLICIES
      match:
        statement_effect: "Allow"
        action_regex: "s3:(Delete.*|Put.*|CreateBucket)"
        resource: "*"
  confidence_rules:
    - level: HIGH
      when: "has_wildcard_resource"
    - level: MEDIUM
      default: true
```

### AWS Wildcard Patterns

Escalato supports wildcard patterns in AWS IAM policies. For example, if a policy contains an action with a wildcard (e.g., `s3:Put*`), Escalato will correctly match it against specific actions in your rules (e.g., `s3:PutObject`).

#### Sensitive Data Access Detection

```yaml
- id: sensitive_data_access
  name: "Sensitive Data Access"
  description: "Role has access to buckets likely containing sensitive data"
  severity: HIGH
  resource_type: Role
  conditions:
    - type: ALL_POLICIES
      match:
        statement_effect: "Allow"
        service: "s3"
        resource_regex: "arn:aws:s3:::.*-(confidential|pii|financial|secure).*"
  confidence_rules:
    - level: HIGH
      default: true
```

## Technical Architecture

Escalato is organized with a clean, modular architecture:

### Core Components

- **Resource Model**: Generic interfaces for AWS resources that decouples validation from specific resource types
- **Rule Engine**: Flexible, expression-based rule evaluation engine
- **Validator Registry**: Plugin-based system for registering condition validators
- **Policy Analyzer**: Sophisticated IAM policy document analysis

### Key Packages

- `cmd`: Command-line interface definitions
- `internal/aws`: AWS client and resource fetching
- `internal/models`: Core data structures
- `internal/rules`: Rule engine, parser, and evaluation
- `internal/validator`: Condition validators
- `internal/utils`: Helper utilities

### Evaluation Process

1. Parse YAML rule definitions
2. Fetch IAM resources from AWS
3. Apply exclusions and filters
4. Evaluate rules against resources
5. Determine confidence levels
6. Generate detailed reporting

## Extending Escalato

### Adding New Resource Types

1. Create a new struct that implements the `models.Resource` interface
2. Update AWS client to fetch and populate the new resource type
3. Register it in the validator

### Adding New Condition Types

1. Add a new constant in `models.ConditionType`
2. Implement a new validator that implements the `validator.ConditionValidator` interface
3. Register it in the validator registry

### Creating Custom Rules

Create a new YAML file with custom rules tailored to your organization's security requirements. Refer to the [Rule Configuration](#rule-configuration) section for details.

## Troubleshooting

### Common Issues

- **AWS Credentials**: Ensure your AWS credentials are correctly configured
- **Permission Denied**: Verify you have sufficient IAM permissions to read IAM data
- **Rule Syntax Errors**: Check your YAML for correct formatting and syntax
- **No Findings Generated**: Verify your rule conditions match expected patterns

### Diagnostic Mode

Enable diagnostic mode for detailed logs:

```bash
escalato validate --diagnostics
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.