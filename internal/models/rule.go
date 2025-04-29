package models

type Severity string


type RuleType string

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
)

type Rule struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Severity    Severity    `yaml:"severity"`
	Type        RuleType    `yaml:"type"`
	Condition   Condition   `yaml:"condition"`
}


type Condition struct {
	Service          string   `yaml:"service,omitempty"`
	Action           string   `yaml:"action,omitempty"`
	Resource         string   `yaml:"resource,omitempty"`
	PrincipalWildcard bool     `yaml:"principal_wildcard,omitempty"`
	Effect           string   `yaml:"effect,omitempty"`
	KeyAge           int      `yaml:"key_age,omitempty"`
	KeyStatus        string   `yaml:"key_status,omitempty"`
	ManagedPolicy    string   `yaml:"managed_policy,omitempty"`
	ExcludePatterns  []string `yaml:"exclude_patterns,omitempty"`
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

type Violation struct {
	RuleName    string   `json:"rule_name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	ResourceName string  `json:"resource_name"`
	ResourceType string  `json:"resource_type"`
	ResourceARN  string  `json:"resource_arn"`
	Details     string   `json:"details,omitempty"`
}