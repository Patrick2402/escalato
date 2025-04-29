package models

import "time"


type User struct {
	UserName    string
	UserId      string
	Arn         string
	CreateDate  time.Time
	Path        string
	Groups      []string
	Policies    []Policy
	AccessKeys  []AccessKey
}


type Policy struct {
	Name      string
	Type      string // "Inline", "Managed"
	Arn       string
	Document  string // Dokument polityki JSON
}


type AccessKey struct {
	Id         string
	Status     string
	CreateDate time.Time
	LastUsed   *LastUsed
}

type LastUsed struct {
	Date      time.Time
	Region    string
	ServiceName string
}