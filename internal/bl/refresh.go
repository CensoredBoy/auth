package bl

import (
	"auth/internal/bl/jwt_service"
	"auth/internal/common"
)

func RefreshTokenHandler(refreshToken common.Token, auth jwt_service.ITokenService) (*common.TokenPair, error) {
	return auth.RefreshTokens(refreshToken)
}
