package tokens_repo

import (
	"auth/internal/common"
	logger "auth/pkg/log"
	"context"
	"errors"
	"github.com/go-redis/redis/v8"
	"strconv"
	"time"
)

var _ IRefreshTokenRepository = (*TokensRedisRepo)(nil)
var _ IAccessTokenRepository = (*TokensRedisRepo)(nil)

type TokensRedisRepo struct {
	client *redis.Client
	logger logger.Logger
}

func NewTokensRedisRepo(client *redis.Client, l logger.Logger) *TokensRedisRepo {
	return &TokensRedisRepo{client: client, logger: l}
}

func (r *TokensRedisRepo) SaveRefreshToken(ctx context.Context, userID common.UserID, token common.Token, expiry time.Duration) error {
	r.logger.Log(
		context.Background(),
		"token_redis_repo",
		logger.LevelInfo,
		"SaveRefreshToken",
		map[string]string{},
	)
	r.logger.Log(
		context.Background(),
		"token_redis_repo",
		logger.LevelDebug,
		"SaveRefreshToken",
		map[string]string{"refresh_token": string(token)},
	)
	err := r.client.Set(ctx, "refresh:"+string(token), int(userID), expiry).Err()
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"SaveRefreshToken",
			map[string]string{"error": err.Error()},
		)
		return err
	}
	return nil
}

func (r *TokensRedisRepo) GetRefreshToken(ctx context.Context, token common.Token) (*common.RefreshTokenData, error) {
	r.logger.Log(
		context.Background(),
		"token_redis_repo",
		logger.LevelInfo,
		"GetRefreshToken",
		map[string]string{},
	)
	r.logger.Log(
		context.Background(),
		"token_redis_repo",
		logger.LevelDebug,
		"GetRefreshToken",
		map[string]string{"refresh_token": string(token)},
	)
	username, err := r.client.Get(ctx, "refresh:"+string(token)).Result()
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"GetRefreshToken",
			map[string]string{"error": err.Error()},
		)
		if !errors.Is(err, redis.Nil) {
			return nil, err
		}
		return &common.RefreshTokenData{Used: true}, nil
	}
	expired := time.Now().Add(-1 * time.Minute)
	ttl, err := r.client.TTL(ctx, "refresh:"+string(token)).Result()
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"GetRefreshToken",
			map[string]string{"error": err.Error()},
		)
		return nil, err
	}
	expired = time.Now().Add(ttl)

	userId, err := strconv.Atoi(username)
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"GetRefreshToken",
			map[string]string{"error": err.Error()},
		)
		return nil, err
	}
	return &common.RefreshTokenData{
		Token:     token,
		UserID:    common.UserID(userId),
		Used:      false,
		ExpiresAt: expired,
	}, nil
}

func (r *TokensRedisRepo) MarkRefreshTokenUsed(ctx context.Context, token common.Token) error {
	r.logger.Log(
		context.Background(),
		"token_redis_repo",
		logger.LevelDebug,
		"MarkRefreshTokenUsed",
		map[string]string{"refresh_token": string(token)},
	)
	err := r.client.Del(ctx, "refresh:"+string(token)).Err()
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"MarkRefreshTokenUsed",
			map[string]string{"error": err.Error()},
		)
	}
	return err
}

func (r *TokensRedisRepo) CheckAccessToken(ctx context.Context, token common.Token) (bool, error) {
	r.logger.Log(
		context.Background(),
		"token_redis_repo",
		logger.LevelDebug,
		"CheckAccessToken",
		map[string]string{"refresh_token": string(token)},
	)
	exists, err := r.client.Exists(ctx, "blacklist:"+string(token)).Result()
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"CheckAccessToken",
			map[string]string{"error": err.Error()},
		)
		return false, err
	}
	return exists == 0, nil
}

func (r *TokensRedisRepo) AddToBlacklist(ctx context.Context, token common.Token) error {
	err := r.client.Set(ctx, "blacklist:"+string(token), "1", 15*time.Minute).Err()
	if err != nil {
		r.logger.Log(
			context.Background(),
			"token_redis_repo",
			logger.LevelError,
			"AddToBlacklist",
			map[string]string{"error": err.Error()},
		)
	}
	return err
}
