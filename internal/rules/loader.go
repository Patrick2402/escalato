package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"escalato/internal/models"
)

func LoadRulesFromFile(filePath string) (*models.RuleSet, error) {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("rules file not found: %s", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading rules file: %w", err)
	}

	var ruleSet models.RuleSet
	err = yaml.Unmarshal(data, &ruleSet)
	if err != nil {
		return nil, fmt.Errorf("error parsing rules file: %w", err)
	}

	err = validateRules(ruleSet.Rules)
	if err != nil {
		return nil, fmt.Errorf("invalid rules: %w", err)
	}

	return &ruleSet, nil
}

func validateRules(rules []models.Rule) error {
	for i, rule := range rules {
		if rule.Name == "" {
			return fmt.Errorf("rule #%d missing name", i+1)
		}
		if rule.Type == "" {
			return fmt.Errorf("rule %s missing type", rule.Name)
		}
		if rule.Severity == "" {
			return fmt.Errorf("rule %s missing severity", rule.Name)
		}

		switch rule.Type {
		case models.RoleTrustPolicy:
			if rule.Condition.Service == "" {
				return fmt.Errorf("rule %s of type %s requires a service condition", rule.Name, rule.Type)
			}
		case models.RolePermissions, models.UserPermissions:
			if rule.Condition.ManagedPolicy != "" {
				continue
			}
            
			if rule.Condition.Service == "" || rule.Condition.Action == "" {
				return fmt.Errorf("rule %s of type %s requires both service and action conditions", rule.Name, rule.Type)
			}
		case models.UserAccessKey:
			if rule.Condition.KeyAge == 0 && rule.Condition.KeyStatus == "" {
				return fmt.Errorf("rule %s of type %s requires either key_age or key_status condition", rule.Name, rule.Type)
			}
		default:
			return fmt.Errorf("rule %s has unknown rule type: %s", rule.Name, rule.Type)
		}
	}

	return nil
