package hasher

import "auth/internal/common"

type IHasher interface {
	GenerateHash(user *common.User) (string, error)
	VerifyPassword(user *common.User, hashedPassword string) bool
}
