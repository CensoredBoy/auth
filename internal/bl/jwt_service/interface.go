package jwt_service

import "auth/internal/common"

type ITokenService interface {
	GenerateTokens(user *common.User) (*common.TokenPair, error)
	ValidateAccessToken(tokenString common.Token) (*common.UserID, error)
	RefreshTokens(refreshToken common.Token) (*common.TokenPair, error)
	RevokeTokens(tokens *common.TokenPair) error
}
