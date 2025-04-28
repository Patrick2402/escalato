package models

import "time"

// Role reprezentuje rolę IAM
type Role struct {
	RoleName    string
	RoleId      string
	Arn         string
	CreateDate  time.Time
	Path        string
	Policies    []Policy
	TrustPolicy string
	LastUsed    *RoleLastUsed
}

type RoleLastUsed struct {
	Date   time.Time
	Region string
}