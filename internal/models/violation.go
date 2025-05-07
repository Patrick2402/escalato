package models

import "time"

// Violation represents a security rule violation
type Violation struct {
	RuleID       string     `json:"rule_id"`
	RuleName     string     `json:"rule_name"`
	Description  string     `json:"description"`
	Severity     Severity   `json:"severity"`
	Confidence   Confidence `json:"confidence"`
	ResourceName string     `json:"resource_name"`
	ResourceType string     `json:"resource_type"`
	ResourceARN  string     `json:"resource_arn"`
	Details      string     `json:"details,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	Timestamp    time.Time  `json:"timestamp"`
}

// ValidationSummary contains aggregate statistics about validation results
type ValidationSummary struct {
	TotalResources        int `json:"total_resources"`
	TotalResourcesByType  map[string]int `json:"total_resources_by_type"`
	TotalViolations       int `json:"total_violations"`
	ViolationsBySeverity  map[Severity]int `json:"violations_by_severity"`
	ViolationsByConfidence map[Confidence]int `json:"violations_by_confidence"`
	ViolationsByRuleID    map[string]int `json:"violations_by_rule_id"`
	ViolationsByResourceType map[string]int `json:"violations_by_resource_type"`
}

// ValidationResults contains the validation summary and detailed violations
type ValidationResults struct {
	Summary    ValidationSummary `json:"summary"`
	Violations []Violation `json:"violations"`
}

// NewValidationResults creates a new empty validation results struct
func NewValidationResults() *ValidationResults {
	return &ValidationResults{
		Summary: ValidationSummary{
			TotalResourcesByType: make(map[string]int),
			ViolationsBySeverity: make(map[Severity]int),
			ViolationsByConfidence: make(map[Confidence]int),
			ViolationsByRuleID: make(map[string]int),
			ViolationsByResourceType: make(map[string]int),
		},
		Violations: []Violation{},
	}
}

// AddViolation adds a violation to the results and updates the summary
func (r *ValidationResults) AddViolation(violation Violation) {
	r.Violations = append(r.Violations, violation)
	r.Summary.TotalViolations++
	r.Summary.ViolationsBySeverity[violation.Severity]++
	r.Summary.ViolationsByConfidence[violation.Confidence]++
	r.Summary.ViolationsByRuleID[violation.RuleID]++
	r.Summary.ViolationsByResourceType[violation.ResourceType]++
}

// AddResource increments the resource count in the summary
func (r *ValidationResults) AddResource(resourceType string) {
	r.Summary.TotalResources++
	r.Summary.TotalResourcesByType[resourceType]++
}