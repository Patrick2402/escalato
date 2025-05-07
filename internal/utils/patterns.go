package utils

import (
	"regexp"
	"strings"
)

// IsWildcardPattern checks if a string contains wildcard characters (* or ?)
func IsWildcardPattern(s string) bool {
	return strings.Contains(s, "*") || strings.Contains(s, "?")
}

// MatchesWildcardPattern checks if a string matches a wildcard pattern
// The pattern can contain * (any number of characters) and ? (exactly one character)
func MatchesWildcardPattern(pattern, s string) bool {
	// Convert wildcard pattern to regex
	regexPattern := wildcardToRegex(pattern)
	
	// Compile the regex
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	
	// Match the string against the regex
	return re.MatchString(s)
}

// wildcardToRegex converts a wildcard pattern to a regex pattern
func wildcardToRegex(pattern string) string {
	// Escape special regex characters
	escapeChars := []string{".", "+", "(", ")", "[", "]", "{", "}", "^", "$", "|"}
	result := pattern
	
	for _, char := range escapeChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}
	
	// Convert wildcard characters to regex equivalents
	result = strings.ReplaceAll(result, "?", ".")
	result = strings.ReplaceAll(result, "*", ".*")
	
	// Add anchors to match the entire string
	return "^" + result + "$"
}

// PatternMatches checks if a string matches a pattern using the specified match type
func PatternMatches(s, pattern, matchType string) bool {
	switch strings.ToLower(matchType) {
	case "exact":
		return s == pattern
	case "prefix":
		return strings.HasPrefix(s, pattern)
	case "suffix":
		return strings.HasSuffix(s, pattern)
	case "contains":
		return strings.Contains(s, pattern)
	case "regex":
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(s)
	case "wildcard":
		return MatchesWildcardPattern(pattern, s)
	default:
		// Default to contains
		return strings.Contains(s, pattern)
	}
}

// MatchAny checks if a string matches any of the provided patterns
func MatchAny(s string, patterns []string, matchType string) bool {
	for _, pattern := range patterns {
		if PatternMatches(s, pattern, matchType) {
			return true
		}
	}
	return false
}

// MatchAll checks if a string matches all of the provided patterns
func MatchAll(s string, patterns []string, matchType string) bool {
	for _, pattern := range patterns {
		if !PatternMatches(s, pattern, matchType) {
			return false
		}
	}
	return true
}

// ContainsAnySubstring checks if a string contains any of the provided substrings
func ContainsAnySubstring(s string, substrings []string) bool {
	for _, substring := range substrings {
		if strings.Contains(s, substring) {
			return true
		}
	}
	return false
}

// ContainsAllSubstrings checks if a string contains all of the provided substrings
func ContainsAllSubstrings(s string, substrings []string) bool {
	for _, substring := range substrings {
		if !strings.Contains(s, substring) {
			return false
		}
	}
	return true
}

// ExtractPattern extracts the first occurrence of a pattern from a string
func ExtractPattern(s, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	
	match := re.FindString(s)
	return match
}

// ExtractAllPatterns extracts all occurrences of a pattern from a string
func ExtractAllPatterns(s, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	
	matches := re.FindAllString(s, -1)
	return matches
}

// IsServiceRole checks if a role name or path indicates it is an AWS service role
func IsServiceRole(roleName, rolePath string) bool {
	// Check common patterns for AWS service roles
	if strings.Contains(rolePath, "/aws-service-role/") {
		return true
	}
	
	if strings.HasPrefix(roleName, "AWSServiceRole") {
		return true
	}
	
	// Common service role name patterns
	serviceRolePrefixes := []string{
		"AWS_",
		"aws-",
		"AmazonSSM",
		"Amazon",
		"CloudFormation",
		"AutoScaling",
		"Lambda",
		"EC2",
	}
	
	for _, prefix := range serviceRolePrefixes {
		if strings.HasPrefix(roleName, prefix) {
			return true
		}
	}
	
	return false
}