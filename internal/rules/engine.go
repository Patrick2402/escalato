package rules

import (
	"fmt"
	"log"
	"time"

	"escalato/internal/models"
)

// RuleEngine is the core component that evaluates rules against resources
type RuleEngine struct {
	registry    *ValidatorRegistry
	evaluator   *ExpressionEvaluator
	diagnostics bool
}

// NewRuleEngine creates a new rule engine with the given validator registry
func NewRuleEngine(registry *ValidatorRegistry, diagnostics bool) *RuleEngine {
	return &RuleEngine{
		registry:    registry,
		evaluator:   NewExpressionEvaluator(),
		diagnostics: diagnostics,
	}
}

// logDebug logs a diagnostic message if diagnostics are enabled
func (e *RuleEngine) logDebug(format string, args ...interface{}) {
	if e.diagnostics {
		log.Printf("[RULE-ENGINE] "+format, args...)
	}
}

// ValidateRule evaluates a single rule against a resource
func (e *RuleEngine) ValidateRule(rule models.Rule, resource models.Resource) ([]models.Violation, error) {
	e.logDebug("Validating rule '%s' against resource %s:%s", 
		rule.Name, resource.GetType(), resource.GetName())
	
	// Skip rules for resources of a different type
	if string(rule.ResourceType) != resource.GetType() {
		e.logDebug("Skipping rule '%s' - resource type mismatch (%s != %s)", 
			rule.Name, rule.ResourceType, resource.GetType())
		return nil, nil
	}
	
	// Create an evaluation context for this resource
	context := NewEvaluationContext(resource)
	
	// Evaluate the rule conditions
	matched, evaluationData, err := e.evaluateConditions(rule.Conditions, context)
	if err != nil {
		return nil, fmt.Errorf("error evaluating conditions for rule '%s': %w", rule.Name, err)
	}
	
	// If rule doesn't match, return without violations
	if !matched {
		e.logDebug("Rule '%s' conditions not matched for resource %s", 
			rule.Name, resource.GetName())
		return nil, nil
	}
	
	e.logDebug("Rule '%s' conditions matched for resource %s, determining confidence level", 
		rule.Name, resource.GetName())
	
	// Rule matched, determine confidence level
	confidence := e.determineConfidence(rule.ConfidenceRules, evaluationData)
	
	// Create the violation
	details := fmt.Sprintf("Resource %s violates rule '%s'", resource.GetName(), rule.Name)
	if conditionDetails, ok := evaluationData["details"].(string); ok && conditionDetails != "" {
		details = conditionDetails
	}
	
	violation := models.Violation{
		RuleID:       rule.ID,
		RuleName:     rule.Name,
		Description:  rule.Description,
		Severity:     rule.Severity,
		Confidence:   confidence,
		ResourceName: resource.GetName(),
		ResourceType: resource.GetType(),
		ResourceARN:  resource.GetARN(),
		Details:      details,
		Context:      evaluationData,
		Timestamp:    time.Now(),
	}
	
	e.logDebug("Created violation for rule '%s', resource %s with confidence %s", 
		rule.Name, resource.GetName(), confidence)
	
	return []models.Violation{violation}, nil
}

// ValidateAll evaluates all rules against all resources
func (e *RuleEngine) ValidateAll(ruleSet *models.RuleSet, resources []models.Resource) (*models.ValidationResults, error) {
	results := models.NewValidationResults()
	
	// Add resources to the summary
	for _, resource := range resources {
		results.AddResource(resource.GetType())
	}
	
	// Evaluate each rule against each resource
	for _, rule := range ruleSet.Rules {
		e.logDebug("Processing rule: %s", rule.Name)
		
		for _, resource := range resources {
			// Skip resources of a different type than the rule is for
			if string(rule.ResourceType) != resource.GetType() {
				continue
			}
			
			violations, err := e.ValidateRule(rule, resource)
			if err != nil {
				e.logDebug("Error validating rule '%s' against resource %s: %v", 
					rule.Name, resource.GetName(), err)
				continue
			}
			
			// Add any violations to the results
			for _, violation := range violations {
				results.AddViolation(violation)
			}
		}
	}
	
	return results, nil
}

// evaluateConditions evaluates a set of conditions against the resource
func (e *RuleEngine) evaluateConditions(conditions []models.Condition, ctx *EvaluationContext) (bool, map[string]interface{}, error) {
	// If there are no conditions, the rule matches
	if len(conditions) == 0 {
		return true, ctx.Data, nil
	}
	
	// Evaluate all conditions
	for _, condition := range conditions {
		validator, err := e.registry.GetValidator(condition.Type)
		if err != nil {
			return false, nil, fmt.Errorf("no validator found for condition type %s: %w", condition.Type, err)
		}
		
		matched, err := validator.Validate(condition, ctx)
		if err != nil {
			return false, nil, fmt.Errorf("error validating condition: %w", err)
		}
		
		if !matched {
			e.logDebug("Condition type %s not matched", condition.Type)
			return false, ctx.Data, nil
		}
		
		e.logDebug("Condition type %s matched", condition.Type)
	}
	
	// All conditions matched
	return true, ctx.Data, nil
}

// determineConfidence determines the confidence level for a rule violation
func (e *RuleEngine) determineConfidence(confidenceRules []models.ConfidenceRule, data map[string]interface{}) models.Confidence {
	// If no confidence rules are defined, default to medium
	if len(confidenceRules) == 0 {
		return models.MediumConfidence
	}
	
	// Look for default confidence first
	defaultConfidence := models.MediumConfidence
	for _, rule := range confidenceRules {
		if rule.Default {
			defaultConfidence = rule.Level
			break
		}
	}
	
	// Evaluate each confidence rule
	for _, rule := range confidenceRules {
		// Skip the default rule since we already handled it
		if rule.Default {
			continue
		}
		
		// If the rule has no "when" expression, skip it
		if rule.When == "" {
			continue
		}
		
		// Evaluate the "when" expression
		result, err := e.evaluator.Evaluate(rule.When, data)
		if err != nil {
			e.logDebug("Error evaluating confidence rule expression '%s': %v", 
				rule.When, err)
			continue
		}
		
		// If the expression evaluates to true, use this confidence level
		if boolResult, ok := result.(bool); ok && boolResult {
			e.logDebug("Confidence rule matched: %s", rule.Level)
			return rule.Level
		}
	}
	
	// No confidence rules matched, use the default
	e.logDebug("Using default confidence level: %s", defaultConfidence)
	return defaultConfidence
}

