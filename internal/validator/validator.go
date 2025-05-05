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
	if role.TrustPolicy == "" {
		logDiagnostic("Role %s has no trust policy document", role.RoleName)
		return
	}

	var trustPolicy map[string]interface{}
	err := json.Unmarshal([]byte(role.TrustPolicy), &trustPolicy)
	if err != nil {
		logDiagnostic("Error parsing trust policy for role %s: %v", role.RoleName, err)
		return
	}

	if stmts, ok := trustPolicy["Statement"].([]interface{}); ok {
		for _, s := range stmts {
			stmt, ok := s.(map[string]interface{})
			if !ok {
				continue
			}

			matchesAction := false
			if actions, ok := stmt["Action"].(string); ok {
				if actions == rule.Condition.Action || rule.Condition.Action == "*" {
					matchesAction = true
					logDiagnostic("Found matching action in trust policy: %s", actions)
				}
			} else if actionArray, ok := stmt["Action"].([]interface{}); ok {
				for _, a := range actionArray {
					if action, ok := a.(string); ok && (action == rule.Condition.Action || rule.Condition.Action == "*") {
						matchesAction = true
						logDiagnostic("Found matching action in trust policy: %s", action)
						break
					}
				}
			}

			matchesService := false
			if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
				if service, ok := principal["Service"]; ok {
					if svcStr, ok := service.(string); ok {
						if strings.Contains(svcStr, rule.Condition.Service) {
							matchesService = true
							logDiagnostic("Found matching service in trust policy: %s", svcStr)
						}
					} else if svcArray, ok := service.([]interface{}); ok {
						for _, s := range svcArray {
							if svc, ok := s.(string); ok && strings.Contains(svc, rule.Condition.Service) {
								matchesService = true
								logDiagnostic("Found matching service in trust policy: %s", svc)
								break
							}
						}
					}
				}
			}

			hasWildcard := false
			if rule.Condition.PrincipalWildcard {
				if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
					if service, ok := principal["Service"]; ok {
						if svcStr, ok := service.(string); ok {
							hasWildcard = strings.Contains(svcStr, "*")
							if hasWildcard {
								logDiagnostic("Found wildcard in Service principal: %s", svcStr)
							}
						} else if svcArray, ok := service.([]interface{}); ok {
							for _, s := range svcArray {
								if svc, ok := s.(string); ok && strings.Contains(svc, "*") {
									hasWildcard = true
									logDiagnostic("Found wildcard in Service principal: %s", svc)
									break
								}
							}
						}
					}

					if aws, ok := principal["AWS"]; ok {
						if awsStr, ok := aws.(string); ok {
							hasWildcard = strings.Contains(awsStr, "*")
							if hasWildcard {
								logDiagnostic("Found wildcard in AWS principal: %s", awsStr)
							}
						} else if awsArray, ok := aws.([]interface{}); ok {
							for _, a := range awsArray {
								if awsItem, ok := a.(string); ok && strings.Contains(awsItem, "*") {
									hasWildcard = true
									logDiagnostic("Found wildcard in AWS principal: %s", awsItem)
									break
								}
							}
						}
					}
				}
			}


			if (matchesAction || rule.Condition.Action == "") && 
			   (matchesService || rule.Condition.Service == "") && 
			   (!rule.Condition.PrincipalWildcard || hasWildcard) {
				
				details := "Role trust policy allows "
				if rule.Condition.Action != "" {
					details += rule.Condition.Action + " "
				}
				if rule.Condition.Service != "" {
					details += "for " + rule.Condition.Service + " "
				}
				if hasWildcard {
					details += "with wildcard principal"
				}

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
				

				break
			} else {
				logDiagnostic("No violation found for this statement. matchesAction=%v, matchesService=%v, hasWildcard=%v", 
					matchesAction, matchesService, hasWildcard)
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

		// if policy.Type == "Inline" && policy.Document != "" {
			if policy.Document != "" {
			logDiagnostic("Analyzing inline policy document for role %s, policy %s", 
				role.RoleName, policy.Name)
			
			hasViolation, details := AnalyzeInlinePolicyDocument(
				policy.Name, 
				policy.Document, 
				rule.Condition.Service, 
				rule.Condition.Action,
			)
			
			if hasViolation {
				logDiagnostic("Violation found in policy document for role %s, policy %s: %s", 
					role.RoleName, policy.Name, details)
				
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
				logDiagnostic("No violation found in policy document for role %s, policy %s", 
					role.RoleName, policy.Name)
			}
		} else {
			logDiagnostic("Using name-based analysis for role %s, policy %s (type: %s, has document: %v)",
				role.RoleName, policy.Name, policy.Type, policy.Document != "")
				
			nameContainsService := strings.Contains(strings.ToLower(policy.Name), strings.ToLower(rule.Condition.Service))
			nameContainsAction := rule.Condition.Action == "*" || strings.Contains(policy.Name, rule.Condition.Action)
			nameContainsFullAccess := strings.Contains(strings.ToLower(policy.Name), "fullaccess") || 
                                     strings.Contains(strings.ToLower(policy.Name), "administratoraccess")
			
			logDiagnostic("Name analysis: containsService=%v, containsAction=%v, containsFullAccess=%v", 
				nameContainsService, nameContainsAction, nameContainsFullAccess)
			
			if (nameContainsService && nameContainsAction) || 
			   (nameContainsService && nameContainsFullAccess) {
				logDiagnostic("Violation detected based on name for role %s, policy %s", 
					role.RoleName, policy.Name)
				
				results.Violations = append(results.Violations, models.Violation{
					RuleName:     rule.Name,
					Description:  rule.Description,
					Severity:     rule.Severity,
					ResourceName: role.RoleName,
					ResourceType: "Role",
					ResourceARN:  role.Arn,
					Details:      "Role has potentially risky policy (based on name): " + policy.Name,
				})
				
				return
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

		// if policy.Type == "Inline" && policy.Document != "" {
		if policy.Document != "" {
			logDiagnostic("Analyzing inline policy document for user %s, policy %s", 
				user.UserName, policy.Name)
			
			hasViolation, details := AnalyzeInlinePolicyDocument(
				policy.Name, 
				policy.Document, 
				rule.Condition.Service, 
				rule.Condition.Action,
			)
			
			if hasViolation {
				logDiagnostic("Violation found in policy document for user %s, policy %s: %s", 
					user.UserName, policy.Name, details)
				
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
			} else {
				logDiagnostic("No violation found in policy document for user %s, policy %s", 
					user.UserName, policy.Name)
			}
		} else {
			logDiagnostic("Using name-based analysis for user %s, policy %s (type: %s, has document: %v)",
				user.UserName, policy.Name, policy.Type, policy.Document != "")
				
			
			nameContainsService := strings.Contains(strings.ToLower(policy.Name), strings.ToLower(rule.Condition.Service))
			nameContainsAction := rule.Condition.Action == "*" || strings.Contains(policy.Name, rule.Condition.Action)
			nameContainsFullAccess := strings.Contains(strings.ToLower(policy.Name), "fullaccess") || 
                                     strings.Contains(strings.ToLower(policy.Name), "administratoraccess")
			
			logDiagnostic("Name analysis: containsService=%v, containsAction=%v, containsFullAccess=%v", 
				nameContainsService, nameContainsAction, nameContainsFullAccess)
			
			if (nameContainsService && nameContainsAction) || 
			   (nameContainsService && nameContainsFullAccess) {
				logDiagnostic("Violation detected based on name for user %s, policy %s", 
					user.UserName, policy.Name)
				
				results.Violations = append(results.Violations, models.Violation{
					RuleName:     rule.Name,
					Description:  rule.Description,
					Severity:     rule.Severity,
					ResourceName: user.UserName,
					ResourceType: "User",
					ResourceARN:  user.Arn,
					Details:      "User has potentially risky policy (based on name): " + policy.Name,
				})
				
				return
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