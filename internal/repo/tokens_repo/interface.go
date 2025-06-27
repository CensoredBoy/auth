package tokens_repo

import (
	"auth/internal/common"
	"context"
	"time"
)

type IRefreshTokenRepository interface {
	SaveRefreshToken(ctx context.Context, userID common.UserID, token common.Token, expiry time.Duration) error
	GetRefreshToken(ctx context.Context, token common.Token) (*common.RefreshTokenData, error)
	MarkRefreshTokenUsed(ctx context.Context, token common.Token) error
}

type IAccessTokenRepository interface {
	CheckAccessToken(ctx context.Context, token common.Token) (bool, error)
	AddToBlacklist(ctx context.Context, token common.Token) error
}
