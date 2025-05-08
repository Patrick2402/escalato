package validator

import (
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"
	"time"

	"escalato/internal/models"
	"escalato/internal/rules"
)

// ResourcePropertyValidator validates conditions on resource properties
type ResourcePropertyValidator struct {
	*BaseValidator
}

// NewResourcePropertyValidator creates a new resource property validator
func NewResourcePropertyValidator(diagnostics bool) *ResourcePropertyValidator {
	return &ResourcePropertyValidator{
		BaseValidator: NewBaseValidator(diagnostics),
	}
}

// Validate checks if a resource property matches a condition
func (v *ResourcePropertyValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	if condition.PropertyPath == "" {
		return false, fmt.Errorf("property_path is required for RESOURCE_PROPERTY condition")
	}
	
	// Get the property value from the resource
	propertyValue, exists := ctx.Resource.GetProperty(condition.PropertyPath)
	if !exists {
		if v.diagnostics {
			log.Printf("[VALIDATOR] Property not found: %s", condition.PropertyPath)
		}
		return false, nil
	}
	
	// If no value to compare against, just check if the property exists
	if condition.Value == nil {
		return true, nil
	}
	
	// Store property value in context for use in expressions
	propertyName := condition.PropertyPath
	if strings.Contains(propertyName, ".") {
		parts := strings.Split(propertyName, ".")
		propertyName = parts[len(parts)-1]
	}
	ctx.Data[propertyName] = propertyValue
	
	// Compare the property value with the expected value
	equal := reflect.DeepEqual(propertyValue, condition.Value)
	
	if v.diagnostics {
		log.Printf("[VALIDATOR] Comparing %v (type %T) with %v (type %T): %v", 
			propertyValue, propertyValue, condition.Value, condition.Value, equal)
	}
	
	return equal, nil
}

// PatternMatchValidator validates string patterns
type PatternMatchValidator struct {
	*BaseValidator
}

// NewPatternMatchValidator creates a new pattern match validator
func NewPatternMatchValidator(diagnostics bool) *PatternMatchValidator {
	return &PatternMatchValidator{
		BaseValidator: NewBaseValidator(diagnostics),
	}
}

// Validate checks if a string matches a pattern
func (v *PatternMatchValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	if condition.PropertyPath == "" {
		return false, fmt.Errorf("property_path is required for PATTERN_MATCH condition")
	}
	
	if condition.Pattern == "" {
		return false, fmt.Errorf("pattern is required for PATTERN_MATCH condition")
	}
	
	// Get the property value from the resource
	propertyValue, exists := ctx.Resource.GetProperty(condition.PropertyPath)
	if !exists {
		if v.diagnostics {
			log.Printf("[VALIDATOR] Property not found: %s", condition.PropertyPath)
		}
		return false, nil
	}
	
	// Convert property to string
	strValue, ok := propertyValue.(string)
	if !ok {
		if v.diagnostics {
			log.Printf("[VALIDATOR] Property is not a string: %s (type %T)", 
				condition.PropertyPath, propertyValue)
		}
		return false, nil
	}
	
	// Store results in context
	propertyName := condition.PropertyPath
	if strings.Contains(propertyName, ".") {
		parts := strings.Split(propertyName, ".")
		propertyName = parts[len(parts)-1]
	}
	ctx.Data[propertyName] = strValue
	
	// Check the pattern
	patternType, _ := condition.Options["type"].(string)
	matched := false
	
	switch patternType {
	case "prefix":
		matched = strings.HasPrefix(strValue, condition.Pattern)
		if v.diagnostics {
			log.Printf("[VALIDATOR] Checking prefix '%s' in '%s': %v", 
				condition.Pattern, strValue, matched)
		}
	case "suffix":
		matched = strings.HasSuffix(strValue, condition.Pattern)
		if v.diagnostics {
			log.Printf("[VALIDATOR] Checking suffix '%s' in '%s': %v", 
				condition.Pattern, strValue, matched)
		}
	case "contains":
		matched = strings.Contains(strValue, condition.Pattern)
		if v.diagnostics {
			log.Printf("[VALIDATOR] Checking contains '%s' in '%s': %v", 
				condition.Pattern, strValue, matched)
		}
	case "exact":
		matched = strValue == condition.Pattern
		if v.diagnostics {
			log.Printf("[VALIDATOR] Checking exact match '%s' == '%s': %v", 
				condition.Pattern, strValue, matched)
		}
	case "regex":
		re, err := regexp.Compile(condition.Pattern)
		if err != nil {
			if v.diagnostics {
				log.Printf("[VALIDATOR] Invalid regex pattern '%s': %v", 
					condition.Pattern, err)
			}
			return false, fmt.Errorf("invalid regex pattern '%s': %w", condition.Pattern, err)
		}
		matched = re.MatchString(strValue)
		if v.diagnostics {
			log.Printf("[VALIDATOR] Checking regex '%s' against '%s': %v", 
				condition.Pattern, strValue, matched)
		}
	default:
		// Default to contains
		matched = strings.Contains(strValue, condition.Pattern)
		if v.diagnostics {
			log.Printf("[VALIDATOR] Checking contains (default) '%s' in '%s': %v", 
				condition.Pattern, strValue, matched)
		}
	}
	
	return matched, nil
}

// AgeValidator validates age-based conditions
type AgeValidator struct {
	*BaseValidator
}

// NewAgeValidator creates a new age validator
func NewAgeValidator(diagnostics bool) *AgeValidator {
	return &AgeValidator{
		BaseValidator: NewBaseValidator(diagnostics),
	}
}

// Validate checks if a timestamp exceeds a threshold age
func (v *AgeValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	if condition.PropertyPath == "" {
		return false, fmt.Errorf("property_path is required for AGE_CONDITION")
	}
	
	if condition.Threshold <= 0 {
		return false, fmt.Errorf("threshold must be positive for AGE_CONDITION")
	}
	
	// Get the property value from the resource
	propertyValue, exists := ctx.Resource.GetProperty(condition.PropertyPath)
	if !exists {
		if v.diagnostics {
			log.Printf("[VALIDATOR] Property not found: %s", condition.PropertyPath)
		}
		return false, nil
	}
	
	// Convert property to time.Time
	var timestamp time.Time
	switch t := propertyValue.(type) {
	case time.Time:
		timestamp = t
	default:
		if v.diagnostics {
			log.Printf("[VALIDATOR] Property is not a timestamp: %s (type %T)", 
				condition.PropertyPath, propertyValue)
		}
		return false, nil
	}
	
	// Calculate age in days
	ageInDays := int(time.Since(timestamp).Hours() / 24)
	
	// Store results in context
	ctx.Data["ageInDays"] = ageInDays
	ctx.Data["timestamp"] = timestamp
	
	// Compare with threshold
	exceedsThreshold := ageInDays > condition.Threshold
	
	if v.diagnostics {
		log.Printf("[VALIDATOR] Age %d days > threshold %d days: %v", 
			ageInDays, condition.Threshold, exceedsThreshold)
	}
	
	return exceedsThreshold, nil
}