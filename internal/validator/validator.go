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
	}

	logDiagnostic("Validation complete. Found %d violations (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)",
		results.Summary.TotalViolations,
		results.Summary.CriticalViolations,
		results.Summary.HighViolations,
		results.Summary.MediumViolations,
		results.Summary.LowViolations,
		results.Summary.InfoViolations)

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

			// Sprawdź Effect - interesują nas tylko Allow
			effect, ok := stmt["Effect"].(string)
			if !ok || effect != "Allow" {
				logDiagnostic("Statement %d does not have Effect=Allow, skipping", stmtIndex)
				continue
			}
			
			// Sprawdź Action - czy pasuje do tego, czego szukamy
			matchesAction := false
			if actions, ok := stmt["Action"].(string); ok {
				logDiagnostic("Action in statement: %s", actions)
				logDiagnostic("Action in rule: %s", rule.Condition.Action)
				if actions == rule.Condition.Action || rule.Condition.Action == "*" {
					matchesAction = true
					logDiagnostic("Found matching action in trust policy: %s", actions)
				}
			} else if actionArray, ok := stmt["Action"].([]interface{}); ok {
				logDiagnostic("Action in statement is an array with %d elements", len(actionArray))
				for _, a := range actionArray {
					if action, ok := a.(string); ok {
						logDiagnostic("Checking action: %s", action)
						if action == rule.Condition.Action || rule.Condition.Action == "*" {
							matchesAction = true
							logDiagnostic("Found matching action in trust policy: %s", action)
							break
						}
					}
				}
			}
			
			// Specjalna logika dla Cross Account Access (aws_principal)
			if rule.Condition.AWSPrincipal {
				// Sprawdzamy czy Principal zawiera AWS
				// hasCrossAccountAccess := false
				var principalAccounts []string
				
				if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
					logDiagnostic("Principal found in statement: %v", principal)
					if aws, ok := principal["AWS"]; ok {
						logDiagnostic("AWS principal found: %v", aws)
						if awsStr, ok := aws.(string); ok {
							// Znaleziono Principal.AWS jako string
							principalAccounts = append(principalAccounts, awsStr)
							logDiagnostic("Found AWS principal: %s", awsStr)
						} else if awsArray, ok := aws.([]interface{}); ok {
							// Znaleziono Principal.AWS jako tablicę
							for _, a := range awsArray {
								if awsItem, ok := a.(string); ok {
									principalAccounts = append(principalAccounts, awsItem)
									logDiagnostic("Found AWS principal in array: %s", awsItem)
								}
							}
						}
					}
				}
				
				// Sprawdź czy istnieje principal, który nie jest na liście wykluczeń
	// In the section for the aws_principal check:
if len(principalAccounts) > 0 && matchesAction {
    hasCrossAccountAccess := false  // Change this to a regular variable without := 
    
    for _, account := range principalAccounts {
        principalExcluded := false
        
        // Sprawdź czy principal jest na liście wykluczeń
        for _, excludePattern := range rule.Condition.ExcludePrincipals {
            if strings.Contains(account, excludePattern) {
                principalExcluded = true
                logDiagnostic("Principal %s is excluded by pattern %s", account, excludePattern)
                break
            }
        }
        
        if !principalExcluded {
            hasCrossAccountAccess = true  // Now we use the variable
            
            details := fmt.Sprintf("Role trust policy allows cross-account access from %s", account)
            
            logDiagnostic("Cross Account violation found for role %s: %s", role.RoleName, details)
            
            results.Violations = append(results.Violations, models.Violation{
                RuleName:     rule.Name,
                Description:  rule.Description,
                Severity:     rule.Severity,
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
				
				// Jeśli dotarliśmy tutaj, to nie znaleźliśmy naruszenia dla aws_principal
				continue
			}

			// Znajdź usługi w Principal.Service
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

			// Sprawdź, czy którykolwiek z principalServices jest na liście wykluczeń
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

			// Sprawdź, czy istnieje sekcja Condition i czy nie jest pusta
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

			// Sprawdzanie wildcard w Principal
			hasWildcardPrincipal := false
			for _, svc := range principalServices {
				if strings.Contains(svc, "*") {
					hasWildcardPrincipal = true
					logDiagnostic("Wildcard found in service principal: %s", svc)
					break
				}
			}
			
			// Sprawdź, czy matchesService dla standardowej metody pasowania
			matchesService := false
			if len(services) == 0 {
				// Jeśli nie określono usług w regule, to każda usługa pasuje
				matchesService = true
				logDiagnostic("No services specified in rule, any service matches")
			} else {
				// Sprawdź, czy którakolwiek z usług w Principal.Service pasuje do usług w regule
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

			// Specjalne sprawdzenie dla require_conditions
			if rule.Condition.RequireConditions && rule.Condition.Action == "sts:AssumeRole" {
				// Dla reguły require_conditions z AssumeRole, nie wymagamy matchesService
				// Sprawdzamy tylko, czy brakuje warunków
				
				if matchesAction && !hasConditions {
					// Jeśli brak warunków, a są wymagane, to jest to naruszenie
					details := fmt.Sprintf("Role trust policy allows AssumeRole without required conditions for service %s", 
						strings.Join(principalServices, ", "))
					
					logDiagnostic("Violation found for role %s: %s", role.RoleName, details)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
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
				// Standardowa logika dla innych typów reguł
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
					
					logDiagnostic("Standard violation found for role %s: %s", role.RoleName, details)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
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
				
				results.Violations = append(results.Violations, models.Violation{
					RuleName:     rule.Name,
					Description:  rule.Description,
					Severity:     rule.Severity,
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
				
				hasViolation, details := AnalyzeInlinePolicyDocument(
					policy.Name, 
					policy.Document, 
					service,
					rule.Condition.Action,
				)
				
				if hasViolation {
					logDiagnostic("Violation found in policy document for role %s, policy %s, service %s: %s", 
						role.RoleName, policy.Name, service, details)
					
					serviceDetails := fmt.Sprintf("Service: %s - %s", service, details)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
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
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
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
				
				results.Violations = append(results.Violations, models.Violation{
					RuleName:     rule.Name,
					Description:  rule.Description,
					Severity:     rule.Severity,
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
				
				hasViolation, details := AnalyzeInlinePolicyDocument(
					policy.Name, 
					policy.Document, 
					service,
					rule.Condition.Action,
				)
				
				if hasViolation {
					logDiagnostic("Violation found in policy document for user %s, policy %s, service %s: %s", 
						user.UserName, policy.Name, service, details)
					
					serviceDetails := fmt.Sprintf("Service: %s - %s", service, details)
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
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
					
					results.Violations = append(results.Violations, models.Violation{
						RuleName:     rule.Name,
						Description:  rule.Description,
						Severity:     rule.Severity,
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
			
			results.Violations = append(results.Violations, models.Violation{
				RuleName:     rule.Name,
				Description:  rule.Description,
				Severity:     rule.Severity,
				ResourceName: user.UserName,
				ResourceType: "User",
				ResourceARN:  user.Arn,
				Details:      fmt.Sprintf("Access key %s is %d days old (threshold: %d days)", 
					key.Id, ageInDays, rule.Condition.KeyAge),
			})
		} else {

			logDiagnostic("Violation: key %s for user %s has status %s", 
				key.Id, user.UserName, key.Status)
			
			results.Violations = append(results.Violations, models.Violation{
				RuleName:     rule.Name,
				Description:  rule.Description,
				Severity:     rule.Severity,
				ResourceName: user.UserName,
				ResourceType: "User",
				ResourceARN:  user.Arn,
				Details:      "Access key " + key.Id + " has status: " + key.Status,
			})
		}
		
		break
	}
}