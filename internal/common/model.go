package common

import (
	"time"
)

type User struct {
	Username string
	Password string
}

type AuthResponse struct {
	Token Token
}

type RefreshTokenData struct {
	Token     Token
	UserID    UserID
	ExpiresAt time.Time
	Used      bool
	IP        string
	UserAgent string
}

type TokenPair struct {
	AccessToken  Token
	RefreshToken Token
	ExpiresAt    int64
}

type Permission struct {
	Read  bool
	Write bool
}

type UserID int
type TeamID int
type OrgID int
type Token string
type UserAccessRequest struct {
	TeamID         *TeamID
	OrganizationID *OrgID
}
