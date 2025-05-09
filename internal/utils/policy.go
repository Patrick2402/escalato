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
// IsActionMatchingAwsPattern sprawdza, czy akcja pasuje do wzorca AWS IAM
func IsActionMatchingAwsPattern(action, pattern string) bool {
    // Obsługa dokładnego dopasowania
    if action == pattern {
        return true
    }
    
    // Obsługa globalnego wildcard
    if pattern == "*" {
        return true
    }
    
    // Obsługa wildcard serwisu (np. cloudtrail:*)
    if strings.HasSuffix(pattern, ":*") {
        patternService := strings.TrimSuffix(pattern, ":*")
        actionParts := strings.Split(action, ":")
        if len(actionParts) == 2 && actionParts[0] == patternService {
            return true
        }
    }
    
    // Obsługa wildcard w akcji (np. cloudtrail:Delete*)
    if strings.Contains(pattern, "*") {
        // Zamień * na .* dla regex
        regexPattern := "^" + strings.Replace(pattern, "*", ".*", -1) + "$"
        re, err := regexp.Compile(regexPattern)
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
	// Obsługa globalnego wildcard i dopasowań ze znakiem *
	if action == "*" {
		return false // Traktuj * jako akcję non-read-only
	}
	
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		return false
	}
	
	service := parts[0]
	actionName := parts[1]
	
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
	
	// Obsługa znanych prefiksów
	for _, prefix := range readOnlyPrefixes {
		if strings.HasPrefix(actionName, prefix) {
			return true
		}
	}
	
	// Obsługa specyficznych akcji dla serwisu
	if specificActions, exists := readonlyServiceActions[service]; exists {
		for _, safeAction := range specificActions {
			if actionName == safeAction {
				return true
			}
		}
	}
	
	// Domyślnie, jeśli nie jesteśmy w stanie jednoznacznie określić - traktuj jako non-read-only
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
			// Zastąp jeden z wildcardów przykładową wartością
			result := strings.Replace(wildcardResource, ":*", ":example", 1)
			return []string{result, wildcardResource}
		}
		
		if strings.Contains(wildcardResource, "/*") {
			// Zastąp wildcard przykładową wartością
			result := strings.Replace(wildcardResource, "/*", "/example-resource", 1)
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
		// Przykładowe akcje dla popularnych serwisów, z podziałem na read-only i modyfikujące
		switch service {
		case "s3":
			return []string{
				// Read-only examples
				"s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation",
				// Modifying examples
				"s3:PutObject", "s3:DeleteObject", "s3:CreateBucket", "s3:DeleteBucket",
			}
		case "ec2":
			return []string{
				// Read-only examples
				"ec2:DescribeInstances", "ec2:DescribeImages", "ec2:DescribeVpcs",
				// Modifying examples
				"ec2:RunInstances", "ec2:TerminateInstances", "ec2:CreateVpc", "ec2:DeleteVpc",
			}
		case "iam":
			return []string{
				// Read-only examples
				"iam:GetUser", "iam:ListUsers", "iam:GetRole", "iam:ListRoles",
				// Modifying examples
				"iam:CreateUser", "iam:DeleteUser", "iam:CreateRole", "iam:DeleteRole", "iam:PutRolePolicy",
			}
		case "logs":
			return []string{
				// Read-only examples
				"logs:GetLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams",
				// Modifying examples
				"logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutLogEvents", "logs:DeleteLogStream",
			}
		case "lambda":
			return []string{
				// Read-only examples
				"lambda:GetFunction", "lambda:ListFunctions", "lambda:GetPolicy",
				// Modifying examples
				"lambda:CreateFunction", "lambda:DeleteFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction",
			}
		case "dynamodb":
			return []string{
				// Read-only examples
				"dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query", "dynamodb:DescribeTable",
				// Modifying examples
				"dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:CreateTable", "dynamodb:DeleteTable",
			}
		default:
			// Ogólne przykłady
			return []string{
				// Read-only examples
				service + ":Get", service + ":List", service + ":Describe", service + ":View", 
				// Modifying examples
				service + ":Create", service + ":Delete", service + ":Update", service + ":Modify",
			}
		}
	} else if strings.HasPrefix(action, "*") {
		suffix := action[1:]
		return []string{
			// Read-only examples with suffix
			service + ":Get" + suffix, service + ":List" + suffix, service + ":Describe" + suffix,
			// Modifying examples with suffix
			service + ":Create" + suffix, service + ":Delete" + suffix, service + ":Update" + suffix,
		}
	} else if strings.HasSuffix(action, "*") {
		prefix := action[:len(action)-1]
		return []string{
			// Examples with prefix
			service + ":" + prefix + "Object", service + ":" + prefix + "Resource",
			service + ":" + prefix + "Function", service + ":" + prefix + "Instance",
		}
	} else if strings.Contains(action, "*") {
		// Złożone wzorce
		parts := strings.Split(action, "*")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]
			return []string{
				// Examples with prefix and suffix
				service + ":" + prefix + "Object" + suffix, service + ":" + prefix + "Resource" + suffix,
				service + ":" + prefix + "Function" + suffix, service + ":" + prefix + "Instance" + suffix,
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


func ShouldMatchServiceAction(action, pattern string) bool {
	if IsReadOnlyAction(action) {
		dangerousPatterns := []string{
			"Delete", "Create", "Update", "Modify", "Put", "Remove", "Set", 
			"Enable", "Disable", "Register", "Deregister", "Associate", 
			"Disassociate", "Attach", "Detach",
		}
		
		for _, dp := range dangerousPatterns {
			if strings.Contains(pattern, dp) {
				return false
			}
		}
	}
	
	return true
}

func IsServiceMatchingRegex(service, pattern string) bool {
	if strings.Contains(pattern, service+":") {
		return true
	}
	
	serviceGroupPattern := regexp.MustCompile(`\((.*?)\):`)
	matches := serviceGroupPattern.FindStringSubmatch(pattern)
	if len(matches) > 1 {
		servicesGroup := matches[1]
		services := strings.Split(servicesGroup, "|")
		for _, s := range services {
			if s == service {
				return true
			}
		}
	}
	
	return false
}

// check if action with wilkdcard matches regex pattern
func IsWildcardActionMatchingRegex(wildCardAction, regexPattern string) bool {
	// global wildcard - always matches
    if wildCardAction == "*" {
        return true
    }
    
    // if no wildcard in action, check if it matches the regex
    if !strings.Contains(wildCardAction, "*") {
        re, err := regexp.Compile(regexPattern)
        return err == nil && re.MatchString(wildCardAction)
    }
    
    // check format service:* 
    if strings.HasSuffix(wildCardAction, ":*") {
        service := strings.TrimSuffix(wildCardAction, ":*")
        return strings.Contains(regexPattern, service+":")
    }
    
    // Check  service:Prefix* e.g. cloudtrail:Delete*
    prefixEndIndex := strings.Index(wildCardAction, "*")
    if prefixEndIndex > 0 {
		// Extract the prefix from the wildcard action
        actionPrefix := wildCardAction[:prefixEndIndex]
        
        parts := strings.Split(wildCardAction, ":")
        if len(parts) == 2 && strings.Contains(regexPattern, parts[0]+":") {
            re := regexp.MustCompile(`\(([^)]+)\)`)
            matches := re.FindAllStringSubmatch(regexPattern, -1)
            
            for _, match := range matches {
                if len(match) > 1 {
                    options := strings.Split(match[1], "|")
                    for _, option := range options {
                        // check if the action prefix matches the option
                        fullOption := parts[0] + ":" + option
                        if strings.HasPrefix(fullOption, actionPrefix) {
                            return true
                        }
                    }
                }
            }
            
            if !strings.Contains(regexPattern, "(") && !strings.Contains(regexPattern, ")") {
                return strings.Contains(regexPattern, actionPrefix)
            }
        }
    }
    
    return false
}