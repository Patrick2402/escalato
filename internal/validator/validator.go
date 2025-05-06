package validator

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"os"

	"escalato/internal/models"
)

var (
	EnableDiagnostics = false
)

func logDiagnostic(format string, args ...interface{}) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-VALIDATOR] "+format+"\n", args...)
	}
}

type ValidationResults struct {
	Summary    ValidationSummary   `json:"summary"`
	Violations []models.Violation  `json:"violations"`
}

type ValidationSummary struct {
	TotalRoles         int `json:"total_roles"`
	TotalUsers         int `json:"total_users"`
	TotalViolations    int `json:"total_violations"`
	CriticalViolations int `json:"critical_violations"`
	HighViolations     int `json:"high_violations"`
	MediumViolations   int `json:"medium_violations"`
	LowViolations      int `json:"low_violations"`
	InfoViolations     int `json:"info_violations"`
	
	// Add confidence summary counts
	HighConfidenceViolations   int `json:"high_confidence_violations"`
	MediumConfidenceViolations int `json:"medium_confidence_violations"`
	LowConfidenceViolations    int `json:"low_confidence_violations"`
	InfoConfidenceViolations   int `json:"info_confidence_violations"`
}

// Helper function to extract services from the condition
func getServicesFromCondition(condition models.Condition) []string {
	var services []string
	
	switch svc := condition.Service.(type) {
	case string:
		services = []string{svc}
	case []interface{}:
		for _, s := range svc {
			if strSvc, ok := s.(string); ok {
				services = append(services, strSvc)
			}
		}
	case []string:
		services = svc
	default:
		// Default to empty slice if not recognized
		logDiagnostic("Unknown service type: %T", condition.Service)
	}
	
	return services
}

// Helper function to check if a role is an AWS managed service role
func isAWSManagedServiceRole(role models.Role) bool {
	// Check if the role path contains aws-service-role
	if strings.Contains(role.Path, "/aws-service-role/") {
		return true
	}
	
	// Check if the role name starts with AWSServiceRole
	if strings.HasPrefix(role.RoleName, "AWSServiceRole") {
		return true
	}
	
	return false
}

// Helper function to calculate confidence for trust policies
func calculateTrustPolicyConfidence(hasWildcardPrincipal bool, hasConditions bool, action string) models.Confidence {
	if hasWildcardPrincipal && !hasConditions && action == "AssumeRole" {
		return models.HighConfidence // Highest risk - wildcard can assume role without conditions
	} else if hasWildcardPrincipal && hasConditions {
		return models.MediumConfidence // Wildcard but with some conditions as mitigations
	} else if !hasWildcardPrincipal && !hasConditions && action == "AssumeRole" {
		return models.MediumConfidence // Specific principal but without conditions
	}
	return models.LowConfidence // Default - other patterns
}

// Helper function to calculate confidence for user access keys
func calculateAccessKeyConfidence(keyAge int, thresholdAge int, status string) models.Confidence {
	if status == "Inactive" {
		return models.HighConfidence // Very confident this is an issue if explicitly checking inactive keys
	}
	
	if keyAge > 0 && thresholdAge > 0 {
		multiplier := float64(keyAge) / float64(thresholdAge)
		if multiplier > 2.0 {
			return models.HighConfidence // Key much older than threshold (over 2x)
		} else if multiplier > 1.2 {
			return models.MediumConfidence // Key moderately older than threshold (1.2-2x)
		}
	}
	
	return models.LowConfidence // Default
}

// Helper function to calculate confidence for name-based policy analysis
func calculateNameBasedConfidence(policyName string, serviceToCheck string, actionToCheck string) models.Confidence {
	nameContainsService := strings.Contains(strings.ToLower(policyName), strings.ToLower(serviceToCheck))
	nameContainsAction := actionToCheck == "*" || strings.Contains(policyName, actionToCheck)
	nameContainsFullAccess := strings.Contains(strings.ToLower(policyName), "fullaccess") || 
							strings.Contains(strings.ToLower(policyName), "administratoraccess")
	
	if nameContainsFullAccess && nameContainsService {
		return models.HighConfidence // Clear indication of full access
	} else if nameContainsService && nameContainsAction {
		return models.MediumConfidence // Specific matches in name
	}
	
	return models.LowConfidence // Default - more ambiguous matches
}

func ValidateAll(rules *models.RuleSet, roles []models.Role, users []models.User) (*ValidationResults, error) {
	logDiagnostic("Starting validation with %d rules for %d roles and %d users", 
		len(rules.Rules), len(roles), len(users))
	
	results := &ValidationResults{
		Summary: ValidationSummary{
			TotalRoles: len(roles),
			TotalUsers: len(users),
		},
	}

	for _, role := range roles {
		logDiagnostic("Validating role: %s", role.RoleName)
		validateRole(rules, role, results)
	}

	for _, user := range users {
		logDiagnostic("Validating user: %s", user.UserName)
		validateUser(rules, user, results)
	}

	results.Summary.TotalViolations = len(results.Violations)
	
	// Count violations by severity and confidence
	for _, violation := range results.Violations {
		switch violation.Severity {
		case models.Critical:
			results.Summary.CriticalViolations++
		case models.High:
			results.Summary.HighViolations++
		case models.Medium:
			results.Summary.MediumViolations++
		case models.Low:
			results.Summary.LowViolations++
		case models.Info:
			results.Summary.InfoViolations++
		}
		
		// Count by confidence level
		switch violation.Confidence {
		case models.HighConfidence:
			results.Summary.HighConfidenceViolations++
		case models.MediumConfidence:
			results.Summary.MediumConfidenceViolations++
		case models.LowConfidence:
			results.Summary.LowConfidenceViolations++
		case models.InfoConfidence:
			results.Summary.InfoConfidenceViolations++
		}
	}

	logDiagnostic("Validation complete. Found %d violations (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)",
		results.Summary.TotalViolations,
		results.Summary.CriticalViolations,
		results.Summary.HighViolations,
		results.Summary.MediumViolations,
		results.Summary.LowViolations,
		results.Summary.InfoViolations)
		
	logDiagnostic("Confidence levels: High: %d, Medium: %d, Low: %d, Info: %d",
		results.Summary.HighConfidenceViolations,
		results.Summary.MediumConfidenceViolations,
		results.Summary.LowConfidenceViolations,
		results.Summary.InfoConfidenceViolations)

	return results, nil
}

func validateRole(rules *models.RuleSet, role models.Role, results *ValidationResults) {
	// Skip AWS managed service roles 
	if isAWSManagedServiceRole(role) {
		logDiagnostic("Skipping AWS managed service role: %s", role.RoleName)
		return
	}

	for _, rule := range rules.Rules {
		if rule.Type == models.RoleTrustPolicy {
			logDiagnostic("Validating trust policy for role %s against rule: %s", 
				role.RoleName, rule.Name)
			validateRoleTrustPolicy(rule, role, results)
		} else if rule.Type == models.RolePermissions {
			logDiagnostic("Validating permissions for role %s against rule: %s", 
				role.RoleName, rule.Name)
			validateRolePermissions(rule, role, results)
		}
	}
}

func validateUser(rules *models.RuleSet, user models.User, results *ValidationResults) {
	for _, rule := range rules.Rules {
		if rule.Type == models.UserPermissions {
			logDiagnostic("Validating permissions for user %s against rule: %s", 
				user.UserName, rule.Name)
			validateUserPermissions(rule, user, results)
		} else if rule.Type == models.UserAccessKey {
			logDiagnostic("Validating access keys for user %s against rule: %s", 
				user.UserName, rule.Name)
			validateUserAccessKeys(rule, user, results)
		}
	}
}

func validateRoleTrustPolicy(rule models.Rule, role models.Role, results *ValidationResults) {
	logDiagnostic("Validating role trust policy for %s, require_conditions=%v, exclude_principals=%v, aws_principal=%v", 
		role.RoleName, rule.Condition.RequireConditions, rule.Condition.ExcludePrincipals, rule.Condition.AWSPrincipal)

	if role.TrustPolicy == "" {
		logDiagnostic("Role %s has no trust policy document", role.RoleName)
		return
	}

	logDiagnostic("Trust policy for role %s: %s", role.RoleName, role.TrustPolicy)

	var trustPolicy map[string]interface{}
	err := json.Unmarshal([]byte(role.TrustPolicy), &trustPolicy)
	if err != nil {
		logDiagnostic("Error parsing trust policy for role %s: %v", role.RoleName, err)
		return
	}

	// Get services from condition
	services := getServicesFromCondition(rule.Condition)
	logDiagnostic("Services to check: %v", services)
	
	if stmts, ok := trustPolicy["Statement"].([]interface{}); ok {
		logDiagnostic("Found %d statements in trust policy", len(stmts))
		for stmtIndex, s := range stmts {
			stmt, ok := s.(map[string]interface{})
			if !ok {
				logDiagnostic("Statement is not a map, skipping")
				continue
			}

			// Check Effect - we care only about Allow
			effect, ok := stmt["Effect"].(string)
			if !ok || effect != "Allow" {
				logDiagnostic("Statement %d does not have Effect=Allow, skipping", stmtIndex)
				continue
			}
			
			// Check Action - does it match what we're looking for
			matchesAction := false
			actionValue := ""
			if actions, ok := stmt["Action"].(string); ok {
				logDiagnostic("Action in statement: %s", actions)
				logDiagnostic("Action in rule: %s", rule.Condition.Action)
				actionValue = actions
				if actions == rule.Condition.Action || rule.Condition.Action == "*" {
					matchesAction = true
					logDiagnostic("Found matching action in trust policy: %s", actions)
				}
			} else if actionArray, ok := stmt["Action"].([]interface{}); ok {
				logDiagnostic("Action in statement is an array with %d elements", len(actionArray))
				for _, a := range actionArray {
					if action, ok := a.(string); ok {
						logDiagnostic("Checking action: %s", action)
						actionValue = action
						if action == rule.Condition.Action || rule.Condition.Action == "*" {
							matchesAction = true
							logDiagnostic("Found matching action in trust policy: %s", action)
							break
						}
					}
				}
			}
			
			// Special logic for Cross Account Access (aws_principal)
			if rule.Condition.AWSPrincipal {
				// Check if Principal contains AWS
				var principalAccounts []string
				
				if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
					logDiagnostic("Principal found in statement: %v", principal)
					if aws, ok := principal["AWS"]; ok {
						logDiagnostic("AWS principal found: %v", aws)
						if awsStr, ok := aws.(string); ok {
							// Found Principal.AWS as string
							principalAccounts = append(principalAccounts, awsStr)
							logDiagnostic("Found AWS principal: %s", awsStr)
						} else if awsArray, ok := aws.([]interface{}); ok {
							// Found Principal.AWS as array
							for _, a := range awsArray {
								if awsItem, ok := a.(string); ok {
									principalAccounts = append(principalAccounts, awsItem)
									logDiagnostic("Found AWS principal in array: %s", awsItem)
								}
							}
						}
					}
				}
				
				// Check if there's a principal not in exclusion list 
				if len(principalAccounts) > 0 && matchesAction {
					hasCrossAccountAccess := false
					
					for _, account := range principalAccounts {
						principalExcluded := false
						
						// Check if principal is in exclusion list
						for _, excludePattern := range rule.Condition.ExcludePrincipals {
							if strings.Contains(account, excludePattern) {
								principalExcluded = true
								logDiagnostic("Principal %s is excluded by pattern %s", account, excludePattern)
								break
							}
						}
						
						if !principalExcluded {
							hasCrossAccountAccess = true
							
							details := fmt.Sprintf("Role trust policy allows cross-account access from %s", account)
							
							// Determine confidence level
							confidence := models.MediumConfidence // Default for cross-account
							if strings.Contains(account, "*") {
								confidence = models.HighConfidence // Higher risk if wildcard in account
							}
							
							logDiagnostic("Cross Account violation found for role %s: %s", role.RoleName, details)
							
							results.Violations = append(results.Violations, models.Violation{
								RuleName:     rule.Name,
								Description:  rule.Description,
								Severity:     rule.Severity,
								Confidence:   confidence,
								ResourceName: role.RoleName,
								ResourceType: "Role",
								ResourceARN:  role.Arn,
								Details:      details,
							})
							
							return
						}
					}
					
					// If we reach here and still haven't found a violation, we can check hasCrossAccountAccess
					if !hasCrossAccountAccess {
						logDiagnostic("No cross-account access violations found for role %s", role.RoleName)
					}
				}
				
				// If we made it here, there's no violation for aws_principal
				continue
			}

			// Find services in Principal.Service
			var principalServices []string
			if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
				logDiagnostic("Principal found in statement: %v", principal)
				if service, ok := principal["Service"]; ok {
					logDiagnostic("Service found in principal: %v", service)
					if svcStr, ok := service.(string); ok {
						principalServices = append(principalServices, svcStr)
						logDiagnostic("Service is a string: %s", svcStr)
					} else if svcArray, ok := service.([]interface{}); ok {
						logDiagnostic("Service is an array with %d elements", len(svcArray))
						for _, s := range svcArray {
							if svc, ok := s.(string); ok {
								principalServices = append(principalServices, svc)
								logDiagnostic("Found service: %s", svc)
							}
						}
					}
				}
			}

			// Check if any principalServices are in exclusion list
			principalExcluded := false
			if len(rule.Condition.ExcludePrincipals) > 0 && len(principalServices) > 0 {
				logDiagnostic("Checking if principals are excluded: %v", principalServices)
				for _, svc := range principalServices {
					for _, excludedPrincipal := range rule.Condition.ExcludePrincipals {
						if strings.Contains(svc, excludedPrincipal) {
							principalExcluded = true
							logDiagnostic("Principal %s is excluded by pattern %s", svc, excludedPrincipal)
							break
						}
					}
					if principalExcluded {
						break
					}
				}
			}
			
			if principalExcluded {
				logDiagnostic("Skipping excluded principal for role %s", role.RoleName)
				continue
			}

			// Check if there's a Condition section and it's not empty
			hasConditions := false
			if conditionObj, ok := stmt["Condition"]; ok && conditionObj != nil {
				logDiagnostic("Condition found in statement: %v", conditionObj)
				if condMap, ok := conditionObj.(map[string]interface{}); ok && len(condMap) > 0 {
					hasConditions = true
					logDiagnostic("Found non-empty conditions in trust policy for role %s", role.RoleName)
				} else {
					logDiagnostic("Condition is empty or not a map")
				}
			} else {
				logDiagnostic("No Condition found in statement")
			}

			// Check for wildcard in Principal
			hasWildcardPrincipal := false
			for _, svc := range principalServices {
				if strings.Contains(svc, "*") {
					hasWildcardPrincipal = true
					logDiagnostic("Wildcard found in service principal: %s", svc)
					break
				}
			}
			
			// Check if matchesService for standard matching method
			matchesService := false
			if len(services) == 0 {
				// If services not specified in rule, any service matches
				matchesService = true
				logDiagnostic("No services specified in rule, any service matches")
			} else {
				// Check if any service in Principal.Service matches services in rule
				for _, svc := range principalServices {
					for _, ruleService := range services {
						if strings.Contains(svc, ruleService) {
							matchesService = true
							logDiagnostic("Service %s matches rule service %s", svc, ruleService)
							break
						}
					}
					if matchesService {
						break
					}
				}
			}

			// Special check for require_conditions
			if rule.Condition.RequireConditions && rule.Condition.Action == "sts:AssumeRole" {
				// For require_conditions rule with AssumeRole, we don't require matchesService
				// Just check if conditions are missing
				
				if matchesAction && !hasConditions {
					// If conditions missing but required, it's a violation
					details := fmt.Sprintf("Role trust policy allows AssumeRole without required conditions for service %s", 
						strings.Join(principalServices, ", "))
					
					// Calculate confidence level
					confidence := calculateTrustPolicyConfidence(hasWildcardPrincipal, hasConditions, actionValue)
					
					logDiagnostic("Violation found for role %s: %s (Confidence: %s)", 
						role.RoleName, details, confidence)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
						Confidence:   confidence,
						ResourceName: role.RoleName,
						ResourceType: "Role",
						ResourceARN:  role.Arn,
						Details:      details,
					})
					
					return
				} else {
					logDiagnostic("Statement has conditions or doesn't match action, not a violation for require_conditions rule")
				}
			} else {
				// Standard logic for other rule types
				if (matchesAction && matchesService) && 
				   (!rule.Condition.PrincipalWildcard || hasWildcardPrincipal) {
					
					details := "Role trust policy allows "
					if rule.Condition.Action != "" {
						details += rule.Condition.Action + " "
					}
					
					if len(principalServices) > 0 {
						details += "for service " + strings.Join(principalServices, ", ")
					}
					
					if hasWildcardPrincipal {
						details += " with wildcard principal"
					}
					
					// Calculate confidence based on trust policy characteristics
					confidence := calculateTrustPolicyConfidence(hasWildcardPrincipal, hasConditions, actionValue)
					
					logDiagnostic("Standard violation found for role %s: %s (Confidence: %s)", 
						role.RoleName, details, confidence)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
						Confidence:   confidence,
						ResourceName: role.RoleName,
						ResourceType: "Role",
						ResourceARN:  role.Arn,
						Details:      details,
					})
					
					return
				} else {
					logDiagnostic("No standard violation: matchesAction=%v, matchesService=%v, wildcard check=%v", 
						matchesAction, matchesService, (!rule.Condition.PrincipalWildcard || hasWildcardPrincipal))
				}
			}
		}
	}
}

func validateRolePermissions(rule models.Rule, role models.Role, results *ValidationResults) {
	if rule.Condition.ManagedPolicy != "" {
		for _, policy := range role.Policies {
			if policy.Type == "Managed" && strings.Contains(policy.Arn, rule.Condition.ManagedPolicy) {
				logDiagnostic("Found managed policy match for role %s: %s", 
					role.RoleName, policy.Name)
				
				// For managed policy matches, the confidence is typically high
				// especially for well-known AWS managed policies
				confidence := models.HighConfidence
				
				results.Violations = append(results.Violations, models.Violation{
					RuleName:     rule.Name,
					Description:  rule.Description,
					Severity:     rule.Severity,
					Confidence:   confidence,
					ResourceName: role.RoleName,
					ResourceType: "Role",
					ResourceARN:  role.Arn,
					Details:      "Role has the managed policy: " + policy.Name,
				})
				
				return
			}
		}

		logDiagnostic("No managed policy match found for role %s", role.RoleName)
		return
	}

	// Get services from condition
	services := getServicesFromCondition(rule.Condition)
	logDiagnostic("Checking role %s for services: %v", role.RoleName, services)
	
	// If no services specified, skip this rule
	if len(services) == 0 {
		logDiagnostic("No services specified for rule %s, skipping", rule.Name)
		return
	}

	for _, service := range services {
		logDiagnostic("Checking service: %s for role %s", service, role.RoleName)
		for _, policy := range role.Policies {
			excluded := false
			for _, pattern := range rule.Condition.ExcludePatterns {
				if strings.Contains(policy.Name, pattern) {
					logDiagnostic("Skipping policy %s for role %s due to exclusion pattern: %s", 
						policy.Name, role.RoleName, pattern)
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}

			if policy.Document != "" {
				logDiagnostic("Analyzing policy document for role %s, policy %s, service %s", 
					role.RoleName, policy.Name, service)
				
				hasViolation, details, confidence := AnalyzeInlinePolicyDocument(
					policy.Name, 
					policy.Document, 
					service,
					rule.Condition.Action,
				)
				
				if hasViolation {
					logDiagnostic("Violation found in policy document for role %s, policy %s, service %s: %s (Confidence: %s)", 
						role.RoleName, policy.Name, service, details, confidence)
					
					serviceDetails := fmt.Sprintf("Service: %s - %s", service, details)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
						Confidence:   confidence,
						ResourceName: role.RoleName,
						ResourceType: "Role",
						ResourceARN:  role.Arn,
						Details:      serviceDetails,
					})
					
					return
				}
			} else {
				logDiagnostic("Using name-based analysis for role %s, policy %s, service %s", 
					role.RoleName, policy.Name, service)
					
				nameContainsService := strings.Contains(strings.ToLower(policy.Name), strings.ToLower(service))
				nameContainsAction := rule.Condition.Action == "*" || strings.Contains(policy.Name, rule.Condition.Action)
				nameContainsFullAccess := strings.Contains(strings.ToLower(policy.Name), "fullaccess") || 
									   strings.Contains(strings.ToLower(policy.Name), "administratoraccess")
				
				logDiagnostic("Name analysis: containsService=%v, containsAction=%v, containsFullAccess=%v", 
					nameContainsService, nameContainsAction, nameContainsFullAccess)
				
				if (nameContainsService && nameContainsAction) || 
				   (nameContainsService && nameContainsFullAccess) {
					logDiagnostic("Violation detected based on name for role %s, policy %s, service %s", 
						role.RoleName, policy.Name, service)
					
					details := fmt.Sprintf("Service: %s - Role has potentially risky policy '%s' (based on name)", 
						service, policy.Name)
					
					// Calculate confidence for name-based analysis
					confidence := calculateNameBasedConfidence(policy.Name, service, rule.Condition.Action)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
						Confidence:   confidence,
						ResourceName: role.RoleName,
						ResourceType: "Role",
						ResourceARN:  role.Arn,
						Details:      details,
					})
					
					return
				}
			}
		}
	}
}

func validateUserPermissions(rule models.Rule, user models.User, results *ValidationResults) {
	if rule.Condition.ManagedPolicy != "" {
		for _, policy := range user.Policies {
			if policy.Type == "Managed" && strings.Contains(policy.Arn, rule.Condition.ManagedPolicy) {
				logDiagnostic("Found managed policy match for user %s: %s", 
					user.UserName, policy.Name)
				
				// High confidence for managed policy matches
				confidence := models.HighConfidence
				
				results.Violations = append(results.Violations, models.Violation{
					RuleName:     rule.Name,
					Description:  rule.Description,
					Severity:     rule.Severity,
					Confidence:   confidence,
					ResourceName: user.UserName,
					ResourceType: "User",
					ResourceARN:  user.Arn,
					Details:      "User has the managed policy: " + policy.Name,
				})
				
				return
			}
		}
		logDiagnostic("No managed policy match found for user %s", user.UserName)
		return
	}

	// Get services from condition
	services := getServicesFromCondition(rule.Condition)
	logDiagnostic("Checking user %s for services: %v", user.UserName, services)
	
	// If no services specified, skip this rule
	if len(services) == 0 {
		logDiagnostic("No services specified for rule %s, skipping", rule.Name)
		return
	}

	for _, service := range services {
		logDiagnostic("Checking service: %s for user %s", service, user.UserName)
		
		for _, policy := range user.Policies {
			excluded := false
			for _, pattern := range rule.Condition.ExcludePatterns {
				if strings.Contains(policy.Name, pattern) {
					logDiagnostic("Skipping policy %s for user %s due to exclusion pattern: %s", 
						policy.Name, user.UserName, pattern)
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}

			if policy.Document != "" {
				logDiagnostic("Analyzing policy document for user %s, policy %s, service %s", 
					user.UserName, policy.Name, service)
				
				hasViolation, details, confidence := AnalyzeInlinePolicyDocument(
					policy.Name, 
					policy.Document, 
					service,
					rule.Condition.Action,
				)
				
				if hasViolation {
					logDiagnostic("Violation found in policy document for user %s, policy %s, service %s: %s (Confidence: %s)", 
						user.UserName, policy.Name, service, details, confidence)
					
					serviceDetails := fmt.Sprintf("Service: %s - %s", service, details)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
						Confidence:   confidence,
						ResourceName: user.UserName,
						ResourceType: "User",
						ResourceARN:  user.Arn,
						Details:      serviceDetails,
					})
					
					return
				}
			} else {
				logDiagnostic("Using name-based analysis for user %s, policy %s, service %s", 
					user.UserName, policy.Name, service)
					
				nameContainsService := strings.Contains(strings.ToLower(policy.Name), strings.ToLower(service))
				nameContainsAction := rule.Condition.Action == "*" || strings.Contains(policy.Name, rule.Condition.Action)
				nameContainsFullAccess := strings.Contains(strings.ToLower(policy.Name), "fullaccess") || 
									   strings.Contains(strings.ToLower(policy.Name), "administratoraccess")
				
				logDiagnostic("Name analysis: containsService=%v, containsAction=%v, containsFullAccess=%v", 
					nameContainsService, nameContainsAction, nameContainsFullAccess)
				
				if (nameContainsService && nameContainsAction) || 
				   (nameContainsService && nameContainsFullAccess) {
					logDiagnostic("Violation detected based on name for user %s, policy %s, service %s", 
						user.UserName, policy.Name, service)
					
					details := fmt.Sprintf("Service: %s - User has potentially risky policy '%s' (based on name)", 
						service, policy.Name)
					
					// Calculate confidence for name-based analysis
					confidence := calculateNameBasedConfidence(policy.Name, service, rule.Condition.Action)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
						Confidence:   confidence,
						ResourceName: user.UserName,
						ResourceType: "User",
						ResourceARN:  user.Arn,
						Details:      details,
					})
					
					return
				}
			}
		}
	}
}

func validateUserAccessKeys(rule models.Rule, user models.User, results *ValidationResults) {
	logDiagnostic("Validating %d access keys for user %s", len(user.AccessKeys), user.UserName)
	
	for _, key := range user.AccessKeys {

		if rule.Condition.KeyStatus != "" && key.Status != rule.Condition.KeyStatus {
			logDiagnostic("Key %s for user %s has status %s, not matching required %s", 
				key.Id, user.UserName, key.Status, rule.Condition.KeyStatus)
			continue
		}

		if rule.Condition.KeyAge > 0 {
			ageInDays := int(time.Since(key.CreateDate).Hours() / 24)
			logDiagnostic("Key %s for user %s is %d days old (threshold: %d days)", 
				key.Id, user.UserName, ageInDays, rule.Condition.KeyAge)
			
			if ageInDays < rule.Condition.KeyAge {
				logDiagnostic("Key %s for user %s is not old enough to violate rule", 
					key.Id, user.UserName)
				continue
			}

			logDiagnostic("Violation: key %s for user %s exceeds age threshold", 
				key.Id, user.UserName)
			
			// Calculate confidence based on how much the key exceeds the threshold
			confidence := calculateAccessKeyConfidence(ageInDays, rule.Condition.KeyAge, key.Status)
			
			results.Violations = append(results.Violations, models.Violation{
				RuleName:     rule.Name,
				Description:  rule.Description,
				Severity:     rule.Severity,
				Confidence:   confidence,
				ResourceName: user.UserName,
				ResourceType: "User",
				ResourceARN:  user.Arn,
				Details:      fmt.Sprintf("Access key %s is %d days old (threshold: %d days)", 
					key.Id, ageInDays, rule.Condition.KeyAge),
			})
		} else {
			// Key status violation
			logDiagnostic("Violation: key %s for user %s has status %s", 
				key.Id, user.UserName, key.Status)
			
			// Typically high confidence for status-based checks
			confidence := models.HighConfidence
			
			results.Violations = append(results.Violations, models.Violation{
				RuleName:     rule.Name,
				Description:  rule.Description,
				Severity:     rule.Severity,
				Confidence:   confidence,
				ResourceName: user.UserName,
				ResourceType: "User",
				ResourceARN:  user.Arn,
				Details:      "Access key " + key.Id + " has status: " + key.Status,
			})
		}
		
		break
	}
}