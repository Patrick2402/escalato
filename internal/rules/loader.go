package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"escalato/internal/models"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromFile loads rules from a YAML file
func LoadRulesFromFile(filePath string) (*models.RuleSet, error) {
	// Check if file exists
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("rules file not found: %s", filePath)
	}

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading rules file: %w", err)
	}

	// Parse the YAML
	var ruleSet models.RuleSet
	err = yaml.Unmarshal(data, &ruleSet)
	if err != nil {
		return nil, fmt.Errorf("error parsing rules file: %w", err)
	}

	// Now call preprocessRules, when ruleSet is already filled with data
	preprocessRules(&ruleSet)

	// Validate and normalize the rules
	err = validateRules(&ruleSet)
	if err != nil {
		return nil, fmt.Errorf("invalid rules: %w", err)
	}

	return &ruleSet, nil
}

// validateRules checks that all rules are valid and normalizes them
func validateRules(ruleSet *models.RuleSet) error {
	for i := range ruleSet.Rules {
		rule := &ruleSet.Rules[i]
		
		// Ensure rule has an ID
		if rule.ID == "" {
			// Generate ID from name if not provided
			rule.ID = strings.ToLower(strings.ReplaceAll(rule.Name, " ", "_"))
		}
		
		// Validate required fields
		if rule.Name == "" {
			return fmt.Errorf("rule #%d missing name", i+1)
		}
		
		if rule.ResourceType == "" {
			return fmt.Errorf("rule '%s' missing resource_type", rule.Name)
		}
		
		if rule.Severity == "" {
			return fmt.Errorf("rule '%s' missing severity", rule.Name)
		}
		
		// Ensure at least one condition
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("rule '%s' has no conditions", rule.Name)
		}
		
		// Validate each condition
		for j, condition := range rule.Conditions {
			if err := validateCondition(condition, rule.Name, j); err != nil {
				return err
			}
		}
		
		// Set default confidence rule if none provided
		if len(rule.ConfidenceRules) == 0 {
			rule.ConfidenceRules = []models.ConfidenceRule{
				{
					Level:   models.MediumConfidence,
					Default: true,
				},
			}
		}
		
		// Ensure at least one default confidence rule
		hasDefault := false
		for _, confRule := range rule.ConfidenceRules {
			if confRule.Default {
				hasDefault = true
				break
			}
		}
		
		if !hasDefault {
			rule.ConfidenceRules = append(rule.ConfidenceRules, models.ConfidenceRule{
				Level:   models.MediumConfidence,
				Default: true,
			})
		}
	}
	
	return nil
}

func validateCondition(condition models.Condition, ruleName string, conditionIndex int) error {
	if condition.Type == "" {
		return fmt.Errorf("rule '%s' condition #%d missing type", ruleName, conditionIndex+1)
	}
	
	switch condition.Type {
	case models.PolicyDocumentCondition:
		if condition.DocumentPath == "" {
			return fmt.Errorf("rule '%s' condition #%d missing document_path", 
				ruleName, conditionIndex+1)
		}
		
		// Validate regex patterns in match criteria
		if condition.Match != nil {
			// Check action_regex if present
			if actionRegex, exists := condition.Match["action_regex"]; exists {
				if actionRegexStr, ok := actionRegex.(string); !ok {
					return fmt.Errorf("rule '%s' condition #%d action_regex must be a string", 
						ruleName, conditionIndex+1)
				} else {
					// Verify regex compiles correctly
					if _, err := regexp.Compile(actionRegexStr); err != nil {
						return fmt.Errorf("rule '%s' condition #%d invalid action_regex: %v", 
							ruleName, conditionIndex+1, err)
					}
				}
			}
			
			// Check resource_regex if present
			if resourceRegex, exists := condition.Match["resource_regex"]; exists {
				if resourceRegexStr, ok := resourceRegex.(string); !ok {
					return fmt.Errorf("rule '%s' condition #%d resource_regex must be a string", 
						ruleName, conditionIndex+1)
				} else {
					// Verify regex compiles correctly
					if _, err := regexp.Compile(resourceRegexStr); err != nil {
						return fmt.Errorf("rule '%s' condition #%d invalid resource_regex: %v", 
							ruleName, conditionIndex+1, err)
					}
				}
			}
		}
	
	case models.AllPoliciesCondition:
		if condition.Match != nil {
			if actionRegex, exists := condition.Match["action_regex"]; exists {
				if actionRegexStr, ok := actionRegex.(string); !ok {
					return fmt.Errorf("rule '%s' condition #%d action_regex must be a string", 
						ruleName, conditionIndex+1)
				} else {
					// Verify regex compiles correctly
					if _, err := regexp.Compile(actionRegexStr); err != nil {
						return fmt.Errorf("rule '%s' condition #%d invalid action_regex: %v", 
							ruleName, conditionIndex+1, err)
					}
				}
			}
			
			// Check resource_regex if present
			if resourceRegex, exists := condition.Match["resource_regex"]; exists {
				if resourceRegexStr, ok := resourceRegex.(string); !ok {
					return fmt.Errorf("rule '%s' condition #%d resource_regex must be a string", 
						ruleName, conditionIndex+1)
				} else {
					// Verify regex compiles correctly
					if _, err := regexp.Compile(resourceRegexStr); err != nil {
						return fmt.Errorf("rule '%s' condition #%d invalid resource_regex: %v", 
							ruleName, conditionIndex+1, err)
					}
				}
			}
		}
	
	case models.ResourcePropertyCondition:
		if condition.PropertyPath == "" {
			return fmt.Errorf("rule '%s' condition #%d missing property_path", 
				ruleName, conditionIndex+1)
		}
	
	case models.PatternMatchCondition:
		if condition.PropertyPath == "" {
			return fmt.Errorf("rule '%s' condition #%d missing property_path", 
				ruleName, conditionIndex+1)
		}
		if condition.Pattern == "" {
			return fmt.Errorf("rule '%s' condition #%d missing pattern", 
				ruleName, conditionIndex+1)
		}
		
		// Validate regex pattern if specified
		if condition.Options != nil {
			if patternType, exists := condition.Options["type"]; exists {
				if patternTypeStr, ok := patternType.(string); ok && patternTypeStr == "regex" {
					if _, err := regexp.Compile(condition.Pattern); err != nil {
						return fmt.Errorf("rule '%s' condition #%d invalid regex pattern: %v", 
							ruleName, conditionIndex+1, err)
					}
				}
			}
		}
	
	case models.AgeCondition:
		if condition.PropertyPath == "" {
			return fmt.Errorf("rule '%s' condition #%d missing property_path", 
				ruleName, conditionIndex+1)
		}
		if condition.Threshold <= 0 {
			return fmt.Errorf("rule '%s' condition #%d threshold must be positive", 
				ruleName, conditionIndex+1)
		}
	
	case models.AndCondition, models.OrCondition:
		if len(condition.Conditions) == 0 {
			return fmt.Errorf("rule '%s' condition #%d (%s) has no sub-conditions", 
				ruleName, conditionIndex+1, condition.Type)
		}
		
		for i, subCondition := range condition.Conditions {
			if err := validateCondition(subCondition, ruleName, i); err != nil {
				return fmt.Errorf("in %s condition: %w", condition.Type, err)
			}
		}
	
	case models.NotCondition:
		if len(condition.Conditions) != 1 {
			return fmt.Errorf("rule '%s' condition #%d (NOT) must have exactly one sub-condition", 
				ruleName, conditionIndex+1)
		}
		
		if err := validateCondition(condition.Conditions[0], ruleName, 0); err != nil {
			return fmt.Errorf("in NOT condition: %w", err)
		}
	
	case models.UnusedPermissionsCondition:
		if condition.Threshold <= 0 {
			condition.Threshold = 90
		}
	
	default:
		return fmt.Errorf("rule '%s' condition #%d unknown condition type: %s", 
			ruleName, conditionIndex+1, condition.Type)
	}
	
	return nil
}

func preprocessRules(ruleSet *models.RuleSet) {
	for i := range ruleSet.Rules {
		rule := &ruleSet.Rules[i]
		
		// Only for rules concerning roles
		if rule.ResourceType == models.RoleResource {
			for j := range rule.Conditions {
				condition := &rule.Conditions[j]
				
				if condition.Type == models.PolicyDocumentCondition && 
				   strings.HasPrefix(condition.DocumentPath, "Policies[") {
					match := condition.Match
					
					condition.Type = models.AllPoliciesCondition
					condition.DocumentPath = "" 
					condition.Match = match     
				}
			}
		}
	}
}