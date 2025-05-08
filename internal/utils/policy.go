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
	// Decode the policy first
	jsonString, err := DecodePolicy(docString)
	if err != nil {
		return nil, fmt.Errorf("error decoding policy: %w", err)
	}
	
	// Parse into the struct
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(jsonString), &doc); err != nil {
		return nil, fmt.Errorf("error parsing policy document: %w", err)
	}
	
	return &doc, nil
}

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
    default:
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
		for _, value := range p {
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
			}
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

// IsReadOnlyAction checks if an IAM action is read-only based on its prefix
func IsReadOnlyAction(action string) bool {
	readOnlyPrefixes := []string{"Get", "List", "Describe", "View", "Read", "Check", "Retrieve", "Monitor"}
	
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		return false
	}
	
	actionName := parts[1]
	
	for _, prefix := range readOnlyPrefixes {
		if strings.HasPrefix(actionName, prefix) {
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
        // Convert AWS wildcard to regex pattern
        awsPattern := "^" + strings.Replace(pattern, "*", ".*", -1) + "$"
        re, err := regexp.Compile(awsPattern)
        if err == nil && re.MatchString(resource) {
            return true
        }
    }
    
    return false
}