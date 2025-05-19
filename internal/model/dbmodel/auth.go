package dbmodel

import "time"

type Auth struct {
	Id        int
	UserId    string
	UserAgent string
	IP        string
	Token     string
	JTI       string
	Revoked   bool
	ExpiresAt time.Time
}
