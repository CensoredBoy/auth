package permission_repo

type Permission struct {
	Read  bool `json:"read"`
	Write bool `json:"write"`
}

type UserAccessRequest struct {
	UserID         int  `json:"user_id"`
	TeamID         *int `json:"team_id"` // может быть nil
	OrganizationID *int `json:"organization_id"`
}
