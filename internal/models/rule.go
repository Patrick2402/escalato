package models

type Severity string
type RuleType string
type Confidence string
type ConditionType string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"

	RoleTrustPolicy  RuleType = "ROLE_TRUST_POLICY"
	RolePermissions  RuleType = "ROLE_PERMISSIONS"
	UserPermissions  RuleType = "USER_PERMISSIONS"
	UserAccessKey    RuleType = "USER_ACCESS_KEY"
	
	// Confidence levels
	HighConfidence   Confidence = "HIGH"
	MediumConfidence Confidence = "MEDIUM"
	LowConfidence    Confidence = "LOW"
	InfoConfidence   Confidence = "INFO"
	
	// Condition types
	PolicyDocumentCondition   ConditionType = "POLICY_DOCUMENT"
	ResourcePropertyCondition ConditionType = "RESOURCE_PROPERTY"
	PatternMatchCondition     ConditionType = "PATTERN_MATCH"
	AgeCondition              ConditionType = "AGE_CONDITION"
	AndCondition              ConditionType = "AND"
	OrCondition               ConditionType = "OR"
	NotCondition              ConditionType = "NOT"
	AllPoliciesCondition      ConditionType = "ALL_POLICIES" 
	UnusedPermissionsCondition ConditionType = "UNUSED_PERMISSIONS" // Add this line
)

type Rule struct {
	ID              string           `yaml:"id"`
	Name            string           `yaml:"name"`
	Description     string           `yaml:"description"`
	Severity        Severity         `yaml:"severity"`
	ResourceType    ResourceType     `yaml:"resource_type"`
	Conditions      []Condition      `yaml:"conditions"`
	ConfidenceRules []ConfidenceRule `yaml:"confidence_rules,omitempty"`
	Tags            []string         `yaml:"tags,omitempty"`
	References      []string         `yaml:"references,omitempty"`
}

type Condition struct {
	Type            ConditionType            `yaml:"type"`
	DocumentPath    string                   `yaml:"document_path,omitempty"`
	PropertyPath    string                   `yaml:"property_path,omitempty"`
	Value           interface{}              `yaml:"value,omitempty"`
	Pattern         string                   `yaml:"pattern,omitempty"`
	Threshold       int                      `yaml:"threshold,omitempty"`
	Match           map[string]interface{}   `yaml:"match,omitempty"`
	Conditions      []Condition              `yaml:"conditions,omitempty"`
	ExpressionValue string                   `yaml:"expression,omitempty"`
	Options         map[string]interface{}   `yaml:"options,omitempty"`
}

type ConfidenceRule struct {
	Level   Confidence `yaml:"level"`
	When    string     `yaml:"when,omitempty"`
	Default bool       `yaml:"default,omitempty"`
}

type RuleSet struct {
	Rules          []Rule    `yaml:"rules"`
	ExcludedRoles  []string  `yaml:"excluded_roles,omitempty"`
	ExcludedUsers  []string  `yaml:"excluded_users,omitempty"`
}