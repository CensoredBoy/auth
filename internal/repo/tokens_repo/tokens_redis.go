package tokens_repo

import (
	"auth/internal/common"
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
}

func NewTokensRedisRepo(client *redis.Client) *TokensRedisRepo {
	return &TokensRedisRepo{client: client}
}

func (r *TokensRedisRepo) SaveRefreshToken(ctx context.Context, userID common.UserID, token common.Token, expiry time.Duration) error {
	err := r.client.Set(ctx, "refresh:"+string(token), int(userID), expiry).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *TokensRedisRepo) GetRefreshToken(ctx context.Context, token common.Token) (*common.RefreshTokenData, error) {
	username, err := r.client.Get(ctx, "refresh:"+string(token)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return nil, err
		}
		return &common.RefreshTokenData{Used: true}, nil
	}
	expired := time.Now().Add(-1 * time.Minute)
	ttl, err := r.client.TTL(ctx, "refresh:"+string(token)).Result()
	if err != nil {
		return nil, err
	}
	expired = time.Now().Add(ttl)

	userId, err := strconv.Atoi(username)
	if err != nil {
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
	return r.client.Del(ctx, "refresh:"+string(token)).Err()
}

func (r *TokensRedisRepo) CheckAccessToken(ctx context.Context, token common.Token) (bool, error) {
	exists, err := r.client.Exists(ctx, "blacklist:"+string(token)).Result()
	if err != nil {
		return false, err
	}
	return exists == 0, nil
}

func (r *TokensRedisRepo) AddToBlacklist(ctx context.Context, token common.Token) error {
	return r.client.Set(ctx, "blacklist:"+string(token), "1", 15*time.Minute).Err()
}
