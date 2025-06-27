package hasher

import (
	"auth/internal/common"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

var _ IHasher = (*BCryptHasher)(nil)

type BCryptHasher struct {
	cost int
}

func NewBCryptHasher(cost int) *BCryptHasher {
	return &BCryptHasher{cost: cost}
}

func (h *BCryptHasher) GenerateHash(user *common.User) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password+user.Username), h.cost)
	if err != nil {
		return "", errors.New("ошибка хеширования")
	}
	return string(hashed), nil
}

func (h *BCryptHasher) VerifyPassword(user *common.User, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password+user.Username))
	return err == nil
}
