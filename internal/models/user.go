package models

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// User represents an IAM user
type User struct {
	UserName    string
	UserId      string
	Arn         string
	CreateDate  time.Time
	Path        string
	Groups      []string
	Policies    []Policy
	AccessKeys  []AccessKey
	metadata    map[string]interface{}
}

// AccessKey represents an IAM access key
type AccessKey struct {
	Id         string
	Status     string
	CreateDate time.Time
	LastUsed   *LastUsed
}

// LastUsed represents information about the last usage of an access key or role
type LastUsed struct {
	Date        time.Time
	Region      string
	ServiceName string
}

// GetType returns the resource type
func (u *User) GetType() string {
	return string(UserResource)
}

// GetName returns the user name
func (u *User) GetName() string {
	return u.UserName
}

// GetARN returns the user ARN
func (u *User) GetARN() string {
	return u.Arn
}

// GetMetadata returns additional resource information
func (u *User) GetMetadata() map[string]interface{} {
	if u.metadata == nil {
		u.metadata = make(map[string]interface{})
	}
	return u.metadata
}

// GetProperty retrieves a property from the user by path
func (u *User) GetProperty(path string) (interface{}, bool) {
	pathParts := strings.Split(path, ".")
	
	value := reflect.ValueOf(u)
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

// GetAccessKeyAge returns the age of an access key in days
func (u *User) GetAccessKeyAge(keyId string) int {
	for _, key := range u.AccessKeys {
		if key.Id == keyId {
			return int(time.Since(key.CreateDate).Hours() / 24)
		}
	}
	return 0
}

// HasInactivaAccessKey checks if the user has any inactive access keys
func (u *User) HasInactiveAccessKey() bool {
	for _, key := range u.AccessKeys {
		if key.Status == "Inactive" {
			return true
		}
	}
	return false
}

// GetOldestAccessKey returns the oldest access key and its age in days
func (u *User) GetOldestAccessKey() (*AccessKey, int) {
	if len(u.AccessKeys) == 0 {
		return nil, 0
	}
	
	oldest := &u.AccessKeys[0]
	oldestAge := int(time.Since(oldest.CreateDate).Hours() / 24)
	
	for i := 1; i < len(u.AccessKeys); i++ {
		age := int(time.Since(u.AccessKeys[i].CreateDate).Hours() / 24)
		if age > oldestAge {
			oldest = &u.AccessKeys[i]
			oldestAge = age
		}
	}
	
	return oldest, oldestAge
}