package models

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Role represents an IAM role
type Role struct {
	RoleName    string
	RoleId      string
	Arn         string
	CreateDate  time.Time
	Path        string
	Policies    []Policy
	TrustPolicy string
	LastUsed    *RoleLastUsed
	metadata    map[string]interface{}
}

// Policy represents an AWS IAM policy attached to a role or user
type Policy struct {
	Name      string
	Type      string // "Inline", "Managed"
	Arn       string
	Document  string // Policy document in JSON format
}

// RoleLastUsed represents information about when a role was last used
type RoleLastUsed struct {
	Date   time.Time
	Region string
}

// GetType returns the resource type
func (r *Role) GetType() string {
	return string(RoleResource)
}

// GetName returns the role name
func (r *Role) GetName() string {
	return r.RoleName
}

// GetARN returns the role ARN
func (r *Role) GetARN() string {
	return r.Arn
}

// GetMetadata returns additional resource information
func (r *Role) GetMetadata() map[string]interface{} {
	if r.metadata == nil {
		r.metadata = make(map[string]interface{})
	}
	return r.metadata
}

// GetProperty retrieves a property from the role by path
func (r *Role) GetProperty(path string) (interface{}, bool) {
	pathParts := strings.Split(path, ".")
	
	value := reflect.ValueOf(r)
	for _, part := range pathParts {
		// Handle array indexing
		if strings.Contains(part, "[") && strings.Contains(part, "]") {
			fieldName := part[:strings.Index(part, "[")]
			indexStr := part[strings.Index(part, "[")+1 : strings.Index(part, "]")]
			index := 0
			fmt.Sscanf(indexStr, "%d", &index)
			
			value = reflect.Indirect(value)
			field := value.FieldByName(fieldName)
			
			if !field.IsValid() {
				return nil, false
			}
			
			if field.Kind() != reflect.Slice && field.Kind() != reflect.Array {
				return nil, false
			}
			
			if index >= field.Len() {
				return nil, false
			}
			
			value = field.Index(index)
		} else {
			value = reflect.Indirect(value)
			field := value.FieldByName(part)
			
			if !field.IsValid() {
				return nil, false
			}
			
			value = field
		}
	}
	
	return value.Interface(), true
}

// IsServiceRole determines if this is an AWS service role
func (r *Role) IsServiceRole() bool {
	// Check if the role path contains aws-service-role
	if strings.Contains(r.Path, "/aws-service-role/") {
		return true
	}
	
	// Check if the role name starts with AWSServiceRole
	if strings.HasPrefix(r.RoleName, "AWSServiceRole") {
		return true
	}
	
	return false
}

// GetRoleLastActive returns when the role was last used, or nil if never used
func (r *Role) GetRoleLastActive() *time.Time {
	if r.LastUsed != nil {
		return &r.LastUsed.Date
	}
	return nil
}

// GetRoleInactiveDays returns the number of days since the role was last used
// Returns -1 if the role has never been used
func (r *Role) GetRoleInactiveDays() int {
	if r.LastUsed == nil {
		return -1
	}
	
	return int(time.Since(r.LastUsed.Date).Hours() / 24)
}