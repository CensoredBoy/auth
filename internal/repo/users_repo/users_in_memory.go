package users_repo

import (
	"auth/internal/common"
	"fmt"
)

var _ IUserRepository = (*InMemoryUsersRepository)(nil)

type User struct {
	Password string
	ID       common.UserID
}
type InMemoryUsersRepository struct {
	rep map[string]User
}

func NewInMemoryUsersRepository(m map[string]User) *InMemoryUsersRepository {
	return &InMemoryUsersRepository{
		rep: m,
	}
}

func (i InMemoryUsersRepository) Get(user *common.User) (string, bool) {
	usr, exists := i.rep[user.Username]
	return usr.Password, exists
}

func (i InMemoryUsersRepository) GetID(user *common.User) common.UserID {
	usr := i.rep[user.Username]
	return usr.ID
}

func (i InMemoryUsersRepository) CreateUser(usr *common.User) error {
	if _, exists := i.rep[usr.Username]; exists {
		return fmt.Errorf("User already exists")
	}
	i.rep[usr.Username] = User{
		Password: usr.Password,
		ID:       2,
	}
	return nil
}
