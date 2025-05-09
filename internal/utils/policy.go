package utils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// PolicyDocument represents an AWS IAM policy document
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Id        string            `json:"Id,omitempty"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a statement in an IAM policy
type PolicyStatement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action,omitempty"`
	NotAction interface{} `json:"NotAction,omitempty"`
	Resource  interface{} `json:"Resource,omitempty"`
	Principal interface{} `json:"Principal,omitempty"`
	Condition interface{} `json:"Condition,omitempty"`
}

// DecodePolicy decodes an AWS IAM policy document from its string representation
func DecodePolicy(policyDocument string) (string, error) {
	// Check if document needs URL decoding
	needsUrlDecoding := strings.Contains(policyDocument, "%")
	
	docToUse := policyDocument
	
	// URL decode if needed
	if needsUrlDecoding {
		unescaped, err := url.QueryUnescape(policyDocument)
		if err != nil {
			return "", fmt.Errorf("error URL-unescaping policy document: %w", err)
		}
		docToUse = unescaped
	}

	// Parse the JSON
	var policy interface{}
	
	// Try to unmarshal directly first
	if err := json.Unmarshal([]byte(docToUse), &policy); err != nil {
		// If that failed, try unwrapping quoted JSON
		if strings.HasPrefix(docToUse, "\"") && strings.HasSuffix(docToUse, "\"") {
			unwrapped := docToUse[1:len(docToUse)-1]
			
			// Replace escaped quotes and backslashes
			unwrapped = strings.ReplaceAll(unwrapped, "\\\"", "\"")
			unwrapped = strings.ReplaceAll(unwrapped, "\\\\", "\\")
			
			if err := json.Unmarshal([]byte(unwrapped), &policy); err != nil {
				return "", fmt.Errorf("error parsing JSON after unwrapping: %w", err)
			}
		} else {
			return "", fmt.Errorf("error parsing policy JSON: %w", err)
		}
	}
	
	// Pretty-print the JSON
	pretty, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error prettifying JSON: %w", err)
	}
	
	return string(pretty), nil
}

// ParsePolicyDocument parses a policy document string into a PolicyDocument struct
func ParsePolicyDocument(docString string) (*PolicyDocument, error) {
	// Obsługa pustych dokumentów
	if len(strings.TrimSpace(docString)) == 0 {
		return &PolicyDocument{Version: "2012-10-17", Statement: []PolicyStatement{}}, nil
	}

	// Decode the policy first
	jsonString, err := DecodePolicy(docString)
	if err != nil {
		return nil, fmt.Errorf("error decoding policy: %w", err)
	}

	// Handle the case when Statement is a single object, not an array
	var singleStatementCheck struct {
		Version   string          `json:"Version"`
		Id        string          `json:"Id,omitempty"`
		Statement json.RawMessage `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(jsonString), &singleStatementCheck); err != nil {
		return nil, fmt.Errorf("error checking statement format: %w", err)
	}

	// Check if the Statement is an array or single object
	isSingleStatement := true
	trimmedStatement := strings.TrimSpace(string(singleStatementCheck.Statement))
	if len(trimmedStatement) > 0 && (trimmedStatement[0] == '[' && trimmedStatement[len(trimmedStatement)-1] == ']') {
		isSingleStatement = false
	}

	// Parse based on type of Statement
	if isSingleStatement {
		// Handle single statement as a special case
		var doc struct {
			Version   string          `json:"Version"`
			Id        string          `json:"Id,omitempty"`
			Statement PolicyStatement `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(jsonString), &doc); err != nil {
			return nil, fmt.Errorf("error parsing single statement policy: %w", err)
		}
		return &PolicyDocument{
			Version:   doc.Version,
			Id:        doc.Id,
			Statement: []PolicyStatement{doc.Statement},
		}, nil
	}

	// Parse into the struct normally for array of statements
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(jsonString), &doc); err != nil {
		return nil, fmt.Errorf("error parsing policy document: %w", err)
	}

	return &doc, nil
}

// GetActionsFromStatement extracts a list of actions from a policy statement
func GetActionsFromStatement(stmt PolicyStatement) []string {
    var actions []string
    
    switch a := stmt.Action.(type) {
    case string:
        actions = append(actions, a)
    case []interface{}:
        for _, action := range a {
            if actionStr, ok := action.(string); ok {
                actions = append(actions, actionStr)
            } 
        }
    case []string:
        actions = append(actions, a...)
    }
    
    return actions
}

// GetResourcesFromStatement extracts a list of resources from a policy statement
func GetResourcesFromStatement(stmt PolicyStatement) []string {
	var resources []string
	
	switch r := stmt.Resource.(type) {
	case string:
		resources = append(resources, r)
	case []interface{}:
		for _, resource := range r {
			if resourceStr, ok := resource.(string); ok {
				resources = append(resources, resourceStr)
			}
		}
	case []string:
		resources = append(resources, r...)
	}
	
	return resources
}

// GetPrincipalsFromStatement extracts a list of principals from a policy statement
func GetPrincipalsFromStatement(stmt PolicyStatement) []string {
	var principals []string
	
	switch p := stmt.Principal.(type) {
	case string:
		principals = append(principals, p)
	case map[string]interface{}:
		// Process AWS, Service, etc. keys
		for key, value := range p {
			// Skip the "NotPrincipal" key if it exists
			if key == "NotPrincipal" {
				continue
			}

			switch v := value.(type) {
			case string:
				principals = append(principals, v)
			case []interface{}:
				for _, item := range v {
					if itemStr, ok := item.(string); ok {
						principals = append(principals, itemStr)
					}
				}
			case []string:
				principals = append(principals, v...)
			case interface{}:
				// Try to convert to string as a fallback
				if str, ok := v.(string); ok {
					principals = append(principals, str)
				}
			}
		}
	case interface{}:
		// Try as a string as fallback
		if principalStr, ok := p.(string); ok {
			principals = append(principals, principalStr)
		}
	}
	
	return principals
}

// HasWildcardResource checks if any resources contain wildcards
func HasWildcardResource(resources []string) bool {
	for _, resource := range resources {
		if resource == "*" || strings.Contains(resource, "*") {
			return true
		}
	}
	return false
}

// HasWildcardPrincipal checks if any principals contain wildcards
func HasWildcardPrincipal(principals []string) bool {
	for _, principal := range principals {
		if principal == "*" || strings.Contains(principal, "*") {
			return true
		}
	}
	return false
}


// IsActionMatchingAwsPattern checks if an action matches an AWS IAM pattern with wildcards
func IsActionMatchingAwsPattern(action, pattern string) bool {
    // Handle exact match
    if action == pattern || pattern == "*" {
        return true
    }
    
    // Handle AWS wildcard pattern
    if strings.Contains(pattern, "*") {
        // Convert AWS wildcard to regex pattern
        awsPattern := "^" + strings.Replace(pattern, "*", ".*", -1) + "$"
        re, err := regexp.Compile(awsPattern)
        if err == nil && re.MatchString(action) {
            return true
        }
    }
    
    return false
}

// IsResourceMatchingAwsPattern checks if a resource ARN matches an AWS IAM pattern with wildcards
func IsResourceMatchingAwsPattern(resource, pattern string) bool {
    if resource == pattern || pattern == "*" {
        return true
    }
    
    if strings.Contains(pattern, "*") {
        awsPattern := "^" + strings.Replace(pattern, "*", ".*", -1) + "$"
        re, err := regexp.Compile(awsPattern)
        if err == nil && re.MatchString(resource) {
            return true
        }
    }
    
    return false
}



func IsReadOnlyAction(action string) bool {
  
    if action == "*" {
        return false 
    }
    
    parts := strings.Split(action, ":")
    if len(parts) != 2 {
        return false
    }
    
    service := parts[0]
    actionName := parts[1]
    
    // Obsługa wildcard service:* (np. logs:*)
    if actionName == "*" {
        return false 
    }
    
    readOnlyPrefixes := []string{
        "Get", "List", "Describe", "View", "Read", "Check", "Retrieve", 
        "Monitor", "Detail", "Lookup", "Search", "Find", "Scan", "Batch",
    }
    
    readonlyServiceActions := map[string][]string{
        "s3": {"GetObject", "GetBucketLocation", "ListBucket", "ListBucketVersions", "GetObjectVersion"},
        "logs": {"FilterLogEvents", "DescribeLogGroups", "DescribeLogStreams", "GetLogEvents"},
        "cloudtrail": {"LookupEvents", "GetTrailStatus", "DescribeTrails", "GetEventSelectors"},
        "lambda": {"GetFunction", "ListFunctions", "GetPolicy", "GetFunctionConfiguration"},
        "iam": {"GetRole", "GetUser", "GetPolicy", "ListRoles", "ListUsers", "GetRolePolicy"},
        "sns": {"GetTopicAttributes", "ListTopics", "ListSubscriptions", "GetSubscriptionAttributes"},
        "cloudwatch": {"GetMetricData", "GetMetricStatistics", "DescribeAlarms", "GetDashboard"},
        "ec2": {"DescribeInstances", "DescribeImages", "DescribeSecurityGroups", "DescribeVpcs"},
        "dynamodb": {"GetItem", "Scan", "Query", "DescribeTable", "ListTables"},
        "kms": {"Decrypt", "DescribeKey", "ListKeys", "GetKeyPolicy", "GetKeyRotationStatus"},
        "sqs": {"GetQueueAttributes", "ListQueues", "ReceiveMessage", "GetQueueUrl"},
        "secretsmanager": {"GetSecretValue", "DescribeSecret", "ListSecrets"},
        "ssm": {"GetParameter", "GetParameters", "DescribeParameters"},
    }
    
    nonReadonlyActions := []string{
        "Delete", "Put", "Create", "Update", "Modify", "Remove", "Apply", "Set", "Start", "Stop",
        "Deploy", "Cancel", "Execute", "Run", "Enable", "Disable", "Register", "Deregister",
        "Associate", "Disassociate", "Attach", "Detach", "Add", "Upload", "Write", "Copy", 
        "Move", "Restore", "Send", "Tag", "Untag", "Publish",
    }
    
    for _, prefix := range nonReadonlyActions {
        if strings.HasPrefix(actionName, prefix) {
            return false
        }
    }
    
    for _, prefix := range readOnlyPrefixes {
        if strings.HasPrefix(actionName, prefix) {
            return true
        }
    }
    
    if specificActions, exists := readonlyServiceActions[service]; exists {
        for _, safeAction := range specificActions {
            if actionName == safeAction {
                return true
            }
        }
    }
    
    return false
}

func ExpandWildcardResource(wildcardResource string) []string {
	if wildcardResource == "*" {
		return []string{
			"arn:aws:s3:::example-bucket",
			"arn:aws:ec2:*:*:instance/*",
			"arn:aws:iam::*:role/*",
		}
	}
	
	if strings.HasPrefix(wildcardResource, "arn:aws:") {
		if strings.Contains(wildcardResource, ":*") {
			result := strings.Replace(wildcardResource, ":*", ":example", 1)
			return []string{result, wildcardResource}
		}
	}
	
	return []string{wildcardResource}
}

func ExpandWildcardAction(wildcardAction string) []string {
	parts := strings.Split(wildcardAction, ":")
	if len(parts) != 2 {
		return []string{wildcardAction}
	}
	
	service := parts[0]
	action := parts[1]
	
	if action == "*" {
		switch service {
		case "s3":
			return []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"}
		case "ec2":
			return []string{"ec2:DescribeInstances", "ec2:RunInstances", "ec2:TerminateInstances"}
		case "iam":
			return []string{"iam:CreateUser", "iam:GetUser", "iam:ListUsers", "iam:DeleteUser"}
		case "logs":
			return []string{"logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutLogEvents", "logs:GetLogEvents"}
		case "lambda":
			return []string{"lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction", "lambda:UpdateFunctionCode"}
		case "dynamodb":
			return []string{"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query"}
		default:
			return []string{
				service + ":Get", 
				service + ":List", 
				service + ":Create", 
				service + ":Delete", 
				service + ":Update",
			}
		}
	} else if strings.HasPrefix(action, "*") {
		suffix := action[1:]
		return []string{
			service + ":Get" + suffix,
			service + ":List" + suffix,
			service + ":Create" + suffix,
			service + ":Update" + suffix,
		}
	} else if strings.HasSuffix(action, "*") {
		prefix := action[:len(action)-1]
		return []string{
			service + ":" + prefix + "Function",
			service + ":" + prefix + "Resource",
			service + ":" + prefix + "Object",
			service + ":" + prefix + "Item",
		}
	} else if strings.Contains(action, "*") {
		parts := strings.Split(action, "*")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]
			return []string{
				service + ":" + prefix + "Function" + suffix,
				service + ":" + prefix + "Resource" + suffix,
				service + ":" + prefix + "Object" + suffix,
				service + ":" + prefix + "Item" + suffix,
			}
		}
	}
	
	return []string{wildcardAction}
}

func Contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}