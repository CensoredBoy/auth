package bl

import (
	"auth/internal/bl/jwt_service"
	"auth/internal/common"
)

func LoginHandler(user *common.User, auth jwt_service.ITokenService) (*common.TokenPair, error) {

	token, err := auth.GenerateTokens(user)
	if err != nil {
		return nil, err
	} else {
		return token, nil
	}
}
