package validator

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"escalato/internal/models"
	"escalato/internal/rules"
	"escalato/internal/utils"
)

// PolicyDocumentValidator validates IAM policy documents
type PolicyDocumentValidator struct {
	*BaseValidator
}

// NewPolicyDocumentValidator creates a new policy document validator
func NewPolicyDocumentValidator(diagnostics bool) ConditionValidator {
	return &PolicyDocumentValidator{
		BaseValidator: NewBaseValidator(diagnostics),
	}
}

// Validate checks if a policy document matches a condition
func (v *PolicyDocumentValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	if condition.DocumentPath == "" {
		return false, fmt.Errorf("document_path is required for POLICY_DOCUMENT condition")
	}

	// Get the policy document from the resource
	docValue, exists := ctx.Resource.GetProperty(condition.DocumentPath)
	if !exists {
		if v.diagnostics {
			log.Printf("[POLICY-VALIDATOR] Document not found: %s", condition.DocumentPath)
		}
		return false, nil
	}

	// Convert to string if needed
	var docString string
	switch d := docValue.(type) {
	case string:
		docString = d
	default:
		if v.diagnostics {
			log.Printf("[POLICY-VALIDATOR] Document is not a string: %s (type %T)",
				condition.DocumentPath, docValue)
		}
		return false, nil
	}

	// Parse the policy document
	doc, err := utils.ParsePolicyDocument(docString)
	if err != nil {
		if v.diagnostics {
			log.Printf("[POLICY-VALIDATOR] Error parsing policy document: %v", err)
		}
		return false, fmt.Errorf("error parsing policy document: %w", err)
	}

	// Match criteria
	matchCriteria := condition.Match
	if matchCriteria == nil {
		matchCriteria = make(map[string]interface{})
	}

	// Process each statement in the document
	matchFound := false
	for _, stmt := range doc.Statement {
		if v.matchesStatement(stmt, matchCriteria) {
			matchFound = true

			// Store information about the matched statement in the context
			ctx.Data["effect"] = stmt.Effect
			ctx.Data["has_conditions"] = stmt.Condition != nil && stmt.Condition != ""

			// Extract information about actions
			actions := utils.GetActionsFromStatement(stmt)
			if len(actions) > 0 {
				ctx.Data["actions"] = actions
				ctx.Data["action_count"] = len(actions)

				readOnlyCount := 0
				var nonReadOnlyActions []string

				for _, action := range actions {
					if utils.IsReadOnlyAction(action) {
						readOnlyCount++
					} else {
						nonReadOnlyActions = append(nonReadOnlyActions, action)
					}
				}

				ctx.Data["read_only_count"] = readOnlyCount
				ctx.Data["non_read_only_count"] = len(actions) - readOnlyCount
				ctx.Data["non_read_only_actions"] = nonReadOnlyActions
			}

			// Extract information about resources
			resources := utils.GetResourcesFromStatement(stmt)
			if len(resources) > 0 {
				ctx.Data["resources"] = resources
				ctx.Data["resource_count"] = len(resources)

				hasWildcardResource := utils.HasWildcardResource(resources)
				ctx.Data["has_wildcard_resource"] = hasWildcardResource
				
				// Count different types of wildcards for confidence rules
				hasGlobalWildcard := false
				hasLeadingOrTrailingWildcard := false
				
				for _, resource := range resources {
					if resource == "*" {
						hasGlobalWildcard = true
						break
					}
					if strings.HasPrefix(resource, "*") || strings.HasSuffix(resource, "*") {
						hasLeadingOrTrailingWildcard = true
					}
				}
				
				ctx.Data["has_global_wildcard"] = hasGlobalWildcard
				ctx.Data["has_leading_or_trailing_wildcard"] = hasLeadingOrTrailingWildcard
			}

			// Extract information about principals
			principals := utils.GetPrincipalsFromStatement(stmt)
			if len(principals) > 0 {
				ctx.Data["principals"] = principals
				ctx.Data["principal_count"] = len(principals)

				hasWildcardPrincipal := utils.HasWildcardPrincipal(principals)
				ctx.Data["has_wildcard_principal"] = hasWildcardPrincipal
			}

			// Check for specific services in actions
			serviceMatches := make(map[string]int)
			for _, action := range actions {
				parts := strings.Split(action, ":")
				if len(parts) == 2 {
					service := parts[0]
					serviceMatches[service]++
				} else if action == "*" {
					// Global wildcard, add the service from the match criteria
					if serviceCriteria, ok := matchCriteria["service"].(string); ok {
						serviceMatches[serviceCriteria]++
					}
				}
			}
			ctx.Data["service_matches"] = serviceMatches

			// Generate detailed information for violations
			var details strings.Builder
			resourceName := ctx.Resource.GetName()

			// Build details string
			if stmt.Effect == "Allow" {
				nonReadOnlyActions, _ := ctx.Data["non_read_only_actions"].([]string)
				hasWildcardResource, _ := ctx.Data["has_wildcard_resource"].(bool)
				hasGlobalWildcard, _ := ctx.Data["has_global_wildcard"].(bool)
				hasWildcardPrincipal, _ := ctx.Data["has_wildcard_principal"].(bool)

				if serviceCriteria, ok := matchCriteria["service"].(string); ok && serviceCriteria != "" {
					// Service-specific actions
					var serviceActions []string
					for _, action := range nonReadOnlyActions {
						if strings.HasPrefix(action, serviceCriteria+":") || action == "*" {
							serviceActions = append(serviceActions, action)
						}
					}

					// Find all actions for this service (including read-only)
					actions, _ := ctx.Data["actions"].([]string)
					var allServiceActions []string
					for _, action := range actions {
						if strings.HasPrefix(action, serviceCriteria+":") || action == "*" {
							allServiceActions = append(allServiceActions, action)
						}
					}

					if len(serviceActions) > 0 {
						details.WriteString(fmt.Sprintf("Resource '%s' allows %d non-read-only %s actions",
							resourceName, len(serviceActions), serviceCriteria))

						// Add action examples
						if len(serviceActions) <= 3 {
							details.WriteString(fmt.Sprintf(" (e.g., %s)", strings.Join(serviceActions, ", ")))
						} else {
							details.WriteString(fmt.Sprintf(" (e.g., %s, ...)", strings.Join(serviceActions[:3], ", ")))
						}
					} else if len(allServiceActions) > 0 {
						// If there are no non-read-only actions, but there are read-only actions
						details.WriteString(fmt.Sprintf("Resource '%s' has read-only access to %s", resourceName, serviceCriteria))

						// Add action examples
						if len(allServiceActions) <= 3 {
							details.WriteString(fmt.Sprintf(" (%s)", strings.Join(allServiceActions, ", ")))
						} else {
							details.WriteString(fmt.Sprintf(" (%s, ...)", strings.Join(allServiceActions[:3], ", ")))
						}
					} else {
						// If no actions found for this service
						details.WriteString(fmt.Sprintf("Resource '%s' has access to %s", resourceName, serviceCriteria))
					}

					if hasGlobalWildcard {
						details.WriteString(" with global wildcard resource")
					} else if hasWildcardResource {
						details.WriteString(" with wildcard in resource")
					}
				} else if actionCriteria, ok := matchCriteria["action"].(string); ok && actionCriteria != "" {
					// For specific action criteria like "s3:*" or "lambda:*"
					service := ""
					if parts := strings.Split(actionCriteria, ":"); len(parts) > 0 {
						service = parts[0]
					}
					
					if service != "" {
						details.WriteString(fmt.Sprintf("Resource '%s' allows wildcard access to %s", 
							resourceName, strings.ToUpper(service)))
					} else {
						details.WriteString(fmt.Sprintf("Resource '%s' allows wildcard access", resourceName))
					}
					
					if hasGlobalWildcard {
						details.WriteString(" with global wildcard resource (*)")
					} else if hasWildcardResource {
						details.WriteString(" with wildcard in resource")
					}
				} else if len(nonReadOnlyActions) > 0 {
					// Default logic for cases without specific service
					details.WriteString(fmt.Sprintf("Resource '%s' allows ", resourceName))

					// Limit to 3 examples
					actionExamples := nonReadOnlyActions
					if len(actionExamples) > 3 {
						actionExamples = actionExamples[:3]
					}

					details.WriteString(fmt.Sprintf("%d non-read-only actions (e.g., %s)",
						len(nonReadOnlyActions), strings.Join(actionExamples, ", ")))

					if hasGlobalWildcard {
						details.WriteString(" with global wildcard resource (*)")
					} else if hasWildcardResource {
						details.WriteString(" with wildcard in resource")
					}
				} else if hasWildcardPrincipal {
					details.WriteString(fmt.Sprintf("Resource '%s' allows wildcard principal", resourceName))
				}
			}

			if details.Len() > 0 {
				ctx.Data["details"] = details.String()
			}

			break
		}
	}

	if v.diagnostics {
		log.Printf("[POLICY-VALIDATOR] Policy document match found: %v", matchFound)
	}

	return matchFound, nil
}

// matchesStatement checks if a statement matches the match criteria
func (v *PolicyDocumentValidator) matchesStatement(stmt utils.PolicyStatement, criteria map[string]interface{}) bool {
	// Check Effect (e.g., "Allow")
	if effectCriteria, ok := criteria["statement_effect"].(string); ok && effectCriteria != "" {
		if stmt.Effect != effectCriteria {
			return false
		}
	}

	// Check Action (e.g., "s3:*")
	if actionCriteria, ok := criteria["action"].(string); ok && actionCriteria != "" {
		actionMatch := false
		actions := utils.GetActionsFromStatement(stmt)

		for _, action := range actions {
			// Direct match or global wildcard
			if action == actionCriteria || action == "*" {
				actionMatch = true
				break
			}

			// Check if policy action has AWS wildcard
			if strings.Contains(action, "*") {
				if utils.IsActionMatchingAwsPattern(actionCriteria, action) {
					actionMatch = true
					break
				}
			}
		}

		if !actionMatch {
			return false
		}
	}

	// Check Action with regex (new feature)
	if actionRegexCriteria, ok := criteria["action_regex"].(string); ok && actionRegexCriteria != "" {
		actionMatch := false
		actions := utils.GetActionsFromStatement(stmt)

		re, err := regexp.Compile(actionRegexCriteria)
		if err == nil {
			for _, action := range actions {
				// Handle global wildcard
				if action == "*" {
					actionMatch = true
					break
				}

				// Handle AWS-style wildcards
				if strings.Contains(action, "*") {
					// Convert AWS wildcard to regex pattern
					awsPattern := "^" + strings.Replace(action, "*", ".*", -1) + "$"
					targetActionRe, err := regexp.Compile(awsPattern)
					
					// Check if this AWS wildcard pattern would include any actions
					// that match our regex criteria
					if err == nil {
						// Try to find a potential match by checking if there's any overlap
						// between the pattern territories
						testActions := []string{
							strings.Replace(actionRegexCriteria, "\\(", "", -1),
							strings.Replace(actionRegexCriteria, "\\)", "", -1),
							strings.Replace(actionRegexCriteria, ".*", "TEST", -1),
							strings.Replace(actionRegexCriteria, "[^:]*", "TEST", -1),
							strings.Replace(actionRegexCriteria, "(.*)", "TEST", -1),
						}
						
						for _, testAction := range testActions {
							// Simplify test action if it's a regex
							testAction = strings.TrimPrefix(testAction, "^")
							testAction = strings.TrimSuffix(testAction, "$")
							testAction = strings.Replace(testAction, "\\", "", -1)
							
							// Check service part for service:* patterns
							if strings.HasSuffix(action, ":*") {
								actionService := strings.TrimSuffix(action, ":*")
								
								// Extract service from test action
								testParts := strings.Split(testAction, ":")
								if len(testParts) > 0 && testParts[0] == actionService {
									actionMatch = true
									break
								}
							}

							// Attempt to match with the AWS pattern
							if targetActionRe.MatchString(testAction) {
								actionMatch = true
								break
							}
						}
						
						if actionMatch {
							break
						}
					}
				}

				// Try direct regex match
				if re.MatchString(action) {
					actionMatch = true
					break
				}
			}
		}

		if !actionMatch {
			return false
		}
	}

	// Check Service (extracted from actions, e.g., "s3")
	if serviceCriteria, ok := criteria["service"].(string); ok && serviceCriteria != "" {
		serviceMatch := false
		actions := utils.GetActionsFromStatement(stmt)

		for _, action := range actions {
			// Handle global wildcard
			if action == "*" {
				serviceMatch = true
				break
			}

			parts := strings.Split(action, ":")
			if len(parts) == 2 {
				service := parts[0]
				// Match exact service
				if service == serviceCriteria {
					serviceMatch = true
					break
				}

				// Match service wildcard (e.g., "service:*")
				if service == "*" {
					serviceMatch = true
					break
				}
			}
		}

		if !serviceMatch {
			return false
		}
	}

	// Check Principal (if specified)
	if principalCriteria, ok := criteria["principal"].(map[string]interface{}); ok && len(principalCriteria) > 0 {
		// Extract principals
		principals := utils.GetPrincipalsFromStatement(stmt)

		// Check for wildcard principal
		if hasWildcard, ok := principalCriteria["has_wildcard"].(bool); ok {
			wildcardFound := utils.HasWildcardPrincipal(principals)

			if hasWildcard != wildcardFound {
				return false
			}
		}
	}

	// Check Resource (if specified)
	if resourceCriteria, ok := criteria["resource"].(string); ok && resourceCriteria != "" {
		resourceMatch := false
		resources := utils.GetResourcesFromStatement(stmt)

		for _, resource := range resources {
			// Direct match or global wildcard
			if resource == resourceCriteria || resource == "*" {
				resourceMatch = true
				break
			}

			// Check if policy resource has AWS wildcard
			if strings.Contains(resource, "*") {
				if utils.IsResourceMatchingAwsPattern(resourceCriteria, resource) {
					resourceMatch = true
					break
				}
			}
		}

		if !resourceMatch {
			return false
		}
	}

	// Check Resource with regex (new feature)
	if resourceRegexCriteria, ok := criteria["resource_regex"].(string); ok && resourceRegexCriteria != "" {
		resourceMatch := false
		resources := utils.GetResourcesFromStatement(stmt)

		re, err := regexp.Compile(resourceRegexCriteria)
		if err == nil {
			for _, resource := range resources {
				if resource == "*" {
					resourceMatch = true
					break
				}

				// Handle AWS-style wildcards
				if strings.Contains(resource, "*") {
					// Same approach as for actions
					awsPattern := "^" + strings.Replace(resource, "*", ".*", -1) + "$"
					targetResourceRe, err := regexp.Compile(awsPattern)
					
					if err == nil {
						// Check for potential overlap between patterns
						testResources := []string{
							strings.Replace(resourceRegexCriteria, "\\(", "", -1),
							strings.Replace(resourceRegexCriteria, "\\)", "", -1),
							strings.Replace(resourceRegexCriteria, ".*", "TEST", -1),
							strings.Replace(resourceRegexCriteria, "(.*)", "TEST", -1),
						}
						
						for _, testResource := range testResources {
							// Simplify test resource if it's a regex
							testResource = strings.TrimPrefix(testResource, "^")
							testResource = strings.TrimSuffix(testResource, "$")
							testResource = strings.Replace(testResource, "\\", "", -1)
							
							// Attempt to match with the AWS pattern
							if targetResourceRe.MatchString(testResource) {
								resourceMatch = true
								break
							}
						}
						
						if resourceMatch {
							break
						}
					}
				}

				// Try direct regex match
				if re.MatchString(resource) {
					resourceMatch = true
					break
				}
			}
		}

		if !resourceMatch {
			return false
		}
	}

	// Check Condition (if specified)
	if conditionCheck, ok := criteria["has_condition"].(bool); ok {
		hasCondition := stmt.Condition != nil && stmt.Condition != ""
		if conditionCheck != hasCondition {
			return false
		}
	}

	return true
}

type AllPoliciesValidator struct {
	*BaseValidator
}

func NewAllPoliciesValidator(diagnostics bool) ConditionValidator {
	return &AllPoliciesValidator{
		BaseValidator: NewBaseValidator(diagnostics),
	}
}

func (v *AllPoliciesValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	v.logDebug("Starting validation for resource %s with ALL_POLICIES", ctx.Resource.GetName())

	policiesValue, exists := ctx.Resource.GetProperty("Policies")
	if !exists {
		v.logDebug("No policies found for resource %s", ctx.Resource.GetName())
		return false, nil
	}
	v.logDebug("Policies type: %T", policiesValue)

	policies, ok := policiesValue.([]models.Policy)
	if !ok {
		v.logDebug("policies is not a slice of Policy: %T", policiesValue)
		return false, nil
	}

	v.logDebug("Checking %d policies for resource %s", len(policies), ctx.Resource.GetName())

	policyValidator := &PolicyDocumentValidator{
		BaseValidator: NewBaseValidator(v.diagnostics),
	}

	for i, policy := range policies {
		v.logDebug("Policy %d: %s, Document length: %d", i, policy.Name, len(policy.Document))

		policyCondition := models.Condition{
			Type:         models.PolicyDocumentCondition,
			DocumentPath: fmt.Sprintf("Policies[%d].Document", i),
			Match:        condition.Match,
		}

		matched, err := policyValidator.Validate(policyCondition, ctx)
		if err != nil {
			v.logDebug("Error validating policy %d: %v", i, err)
			continue
		}

		if matched {
			v.logDebug("Policy %d matched for resource %s", i, ctx.Resource.GetName())
			return true, nil
		}
	}

	return false, nil
}