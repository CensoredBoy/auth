package jwt_service

import (
	"auth/internal/bl/hasher"
	"auth/internal/common"
	"auth/internal/repo/tokens_repo"
	"auth/internal/repo/users_repo"
	logger "auth/pkg/log"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"strconv"
	"time"
)

var _ ITokenService = (*JWTAuthService)(nil)

type JWTAuthService struct {
	userRepo         users_repo.IUserRepository
	h                hasher.IHasher
	accessSecret     []byte
	refreshSecret    []byte
	accessExpiry     time.Duration // 15 минут
	refreshExpiry    time.Duration
	refreshTokenRepo tokens_repo.IRefreshTokenRepository
	logger           logger.Logger
}

func NewJWTAuthService(accessSecret, refreshSecret []byte, refreshRepo tokens_repo.IRefreshTokenRepository, userRepo users_repo.IUserRepository, h hasher.IHasher, l logger.Logger) *JWTAuthService {
	return &JWTAuthService{
		userRepo:         userRepo,
		h:                h,
		accessSecret:     accessSecret,
		refreshSecret:    refreshSecret,
		accessExpiry:     15 * time.Minute,
		refreshExpiry:    7 * 24 * time.Hour,
		refreshTokenRepo: refreshRepo,
		logger:           l,
	}
}

func (s *JWTAuthService) GenerateTokens(user *common.User) (*common.TokenPair, error) {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"GenerateTokens",
		map[string]string{},
	)
	pwd, exists := s.userRepo.Get(user)
	if !exists {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"GenerateTokens",
			map[string]string{"error": "User not exists"},
		)
		return nil, fmt.Errorf("User not exists")
	}
	passwordCorrect := s.h.VerifyPassword(user, pwd)
	if !passwordCorrect {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"GenerateTokens",
			map[string]string{"error": "Password not correct"},
		)
		return nil, fmt.Errorf("Password not correct")
	}
	id := s.userRepo.GetID(user)
	return s.generateTokensByID(id)
}
func (s *JWTAuthService) generateTokensByID(userID common.UserID) (*common.TokenPair, error) {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"generateTokensByID",
		map[string]string{},
	)
	accessToken, err := s.generateJWT(userID, s.accessExpiry)
	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"generateTokensByID",
			map[string]string{"error": fmt.Errorf("access token error: %w", err).Error()},
		)
		return nil, fmt.Errorf("access token error: %w", err)
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"generateTokensByID",
			map[string]string{"error": fmt.Errorf("refresh token error: %w", err).Error()},
		)
		return nil, fmt.Errorf("refresh token error: %w", err)
	}

	err = s.refreshTokenRepo.SaveRefreshToken(context.Background(), userID, common.Token(refreshToken), s.refreshExpiry)
	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"generateTokensByID",
			map[string]string{"error": fmt.Errorf("save refresh error: %w", err).Error()},
		)
		return nil, fmt.Errorf("save refresh error: %w", err)
	}

	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelDebug,
		"generateTokensByID",
		map[string]string{"tokens": fmt.Sprintf("access_token: %s, refresh_token: %s", accessToken, refreshToken)},
	)
	return &common.TokenPair{
		AccessToken:  common.Token(accessToken),
		RefreshToken: common.Token(refreshToken),
		ExpiresAt:    time.Now().Add(s.accessExpiry).Unix(),
	}, nil
}
func (s *JWTAuthService) ValidateRefreshToken(tokenString common.Token) (*common.RefreshTokenData, error) {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"ValidateRefreshToken",
		map[string]string{},
	)
	tokenData, err := s.refreshTokenRepo.GetRefreshToken(context.Background(), tokenString)
	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"ValidateRefreshToken",
			map[string]string{
				"error": errors.New("token not found").Error(),
			},
		)
		return nil, errors.New("token not found")
	}

	if time.Now().After(tokenData.ExpiresAt) {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"ValidateRefreshToken",
			map[string]string{
				"error": errors.New("token expired").Error(),
			},
		)
		return nil, errors.New("token expired")
	}

	if tokenData.Used {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"ValidateRefreshToken",
			map[string]string{
				"error": errors.New("token already used").Error(),
			},
		)
		return nil, errors.New("token already used")
	}

	return tokenData, nil
}

// Обновление пары токенов
func (s *JWTAuthService) RefreshTokens(refreshToken common.Token) (*common.TokenPair, error) {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"RefreshTokens",
		map[string]string{},
	)
	tokenData, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"RefreshTokens",
			map[string]string{
				"error": fmt.Errorf("invalid refresh token: %w", err).Error(),
			},
		)
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if time.Now().After(tokenData.ExpiresAt) {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"RefreshTokens",
			map[string]string{
				"error": errors.New("refresh token expired").Error(),
			},
		)
		return nil, errors.New("refresh token expired")
	}

	err = s.refreshTokenRepo.MarkRefreshTokenUsed(context.Background(), refreshToken)
	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"RefreshTokens",
			map[string]string{
				"error": fmt.Errorf("refresh token update error: %w", err).Error(),
			},
		)
		return nil, fmt.Errorf("refresh token update error: %w", err)
	}

	return s.generateTokensByID(tokenData.UserID)
}

func (s *JWTAuthService) ValidateAccessToken(tokenString common.Token) (*common.UserID, error) {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"ValidateAccessToken",
		map[string]string{},
	)
	token, err := jwt.ParseWithClaims(string(tokenString), &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			s.logger.Log(
				context.Background(),
				"jwt_auth_service",
				logger.LevelError,
				"ValidateAccessToken",
				map[string]string{
					"error": fmt.Errorf("unexpected signing method: %v", token.Header["alg"]).Error(),
				},
			)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.accessSecret, nil
	})

	if err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"ValidateAccessToken",
			map[string]string{
				"error": err.Error(),
			},
		)
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, errors.New("invalid token format")
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token expired")
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		if claims.Subject == "" {
			s.logger.Log(
				context.Background(),
				"jwt_auth_service",
				logger.LevelError,
				"ValidateAccessToken",
				map[string]string{
					"error": errors.New("missing subject in token").Error(),
				},
			)
			return nil, errors.New("missing subject in token")
		}
		id, err := strconv.Atoi(claims.Subject)
		if err != nil {
			s.logger.Log(
				context.Background(),
				"jwt_auth_service",
				logger.LevelError,
				"ValidateAccessToken",
				map[string]string{
					"error": err.Error(),
				},
			)
			return nil, err
		}
		i := common.UserID(id)
		return &i, nil
	}

	return nil, errors.New("invalid token claims")
}

func (s *JWTAuthService) RevokeTokens(tokens *common.TokenPair) error {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"RevokeTokens",
		map[string]string{},
	)
	if err := s.refreshTokenRepo.MarkRefreshTokenUsed(context.Background(), tokens.RefreshToken); err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelError,
			"RevokeTokens",
			map[string]string{
				"error": err.Error(),
			},
		)
		return err
	}
	return nil
}

func (s *JWTAuthService) generateJWT(userID common.UserID, expiry time.Duration) (common.Token, error) {
	s.logger.Log(
		context.Background(),
		"jwt_auth_service",
		logger.LevelInfo,
		"generateJWT",
		map[string]string{},
	)
	claims := jwt.RegisteredClaims{
		Subject:   strconv.Itoa(int(userID)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		ID:        uuid.NewString(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString(s.accessSecret)
	return common.Token(t), err
}

func (s *JWTAuthService) generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		s.logger.Log(
			context.Background(),
			"jwt_auth_service",
			logger.LevelInfo,
			"generateRefreshToken",
			map[string]string{
				"error": err.Error(),
			},
		)
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
