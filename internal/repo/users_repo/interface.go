package users_repo

import "auth/internal/common"

type IUserRepository interface {
	Get(user *common.User) (string, bool)
	GetID(user *common.User) common.UserID
	CreateUser(user *common.User) error
}
