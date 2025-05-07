package models

// Resource defines the interface that all resources must implement
type Resource interface {
	// GetType returns the type of resource (e.g., "Role", "User")
	GetType() string
	
	// GetName returns the resource name
	GetName() string
	
	// GetARN returns the resource ARN
	GetARN() string
	
	// GetProperty retrieves a property from the resource by path
	// e.g., "Policies[0].Document", "TrustPolicy", etc.
	GetProperty(path string) (interface{}, bool)
	
	// GetMetadata retrieves additional resource information
	GetMetadata() map[string]interface{}
}

// ResourceType represents the type of AWS resource
type ResourceType string

const (
	RoleResource ResourceType = "Role"
	UserResource ResourceType = "User"
)

// ResourceProvider is an interface for anything that can provide resources
type ResourceProvider interface {
	// GetResources returns all resources of a given type
	GetResources(resourceType ResourceType) ([]Resource, error)
}