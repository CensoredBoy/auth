package jwt_service

import (
	"auth/internal/bl/hasher"
	"auth/internal/common"
	"auth/internal/repo/tokens_repo"
	"auth/internal/repo/users_repo"
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
}

func NewJWTAuthService(accessSecret, refreshSecret []byte, refreshRepo tokens_repo.IRefreshTokenRepository, userRepo users_repo.IUserRepository, h hasher.IHasher) *JWTAuthService {
	return &JWTAuthService{
		userRepo:         userRepo,
		h:                h,
		accessSecret:     accessSecret,
		refreshSecret:    refreshSecret,
		accessExpiry:     15 * time.Minute,
		refreshExpiry:    7 * 24 * time.Hour,
		refreshTokenRepo: refreshRepo,
	}
}

func (s *JWTAuthService) GenerateTokens(user *common.User) (*common.TokenPair, error) {
	pwd, exists := s.userRepo.Get(user)
	if !exists {
		return nil, fmt.Errorf("User not exists")
	}
	passwordCorrect := s.h.VerifyPassword(user, pwd)
	if !passwordCorrect {
		return nil, fmt.Errorf("Password not correct")
	}
	id := s.userRepo.GetID(user)
	return s.generateTokensByID(id)
}
func (s *JWTAuthService) generateTokensByID(userID common.UserID) (*common.TokenPair, error) {
	accessToken, err := s.generateJWT(userID, s.accessExpiry)
	if err != nil {
		return nil, fmt.Errorf("access token error: %w", err)
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("refresh token error: %w", err)
	}

	err = s.refreshTokenRepo.SaveRefreshToken(context.Background(), userID, common.Token(refreshToken), s.refreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("save refresh error: %w", err)
	}

	return &common.TokenPair{
		AccessToken:  common.Token(accessToken),
		RefreshToken: common.Token(refreshToken),
		ExpiresAt:    time.Now().Add(s.accessExpiry).Unix(),
	}, nil
}
func (s *JWTAuthService) ValidateRefreshToken(tokenString common.Token) (*common.RefreshTokenData, error) {

	tokenData, err := s.refreshTokenRepo.GetRefreshToken(context.Background(), tokenString)
	if err != nil {
		return nil, errors.New("token not found")
	}

	if time.Now().After(tokenData.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	if tokenData.Used {
		return nil, errors.New("token already used")
	}

	return tokenData, nil
}

// Обновление пары токенов
func (s *JWTAuthService) RefreshTokens(refreshToken common.Token) (*common.TokenPair, error) {
	tokenData, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if time.Now().After(tokenData.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	err = s.refreshTokenRepo.MarkRefreshTokenUsed(context.Background(), refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token update error: %w", err)
	}

	return s.generateTokensByID(tokenData.UserID)
}

func (s *JWTAuthService) ValidateAccessToken(tokenString common.Token) (*common.UserID, error) {
	token, err := jwt.ParseWithClaims(string(tokenString), &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.accessSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, errors.New("invalid token format")
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token expired")
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		if claims.Subject == "" {
			return nil, errors.New("missing subject in token")
		}
		id, err := strconv.Atoi(claims.Subject)
		if err != nil {
			return nil, err
		}
		i := common.UserID(id)
		return &i, nil
	}

	return nil, errors.New("invalid token claims")
}

func (s *JWTAuthService) RevokeTokens(tokens *common.TokenPair) error {
	if err := s.refreshTokenRepo.MarkRefreshTokenUsed(context.Background(), tokens.RefreshToken); err != nil {
		return err
	}
	return nil
}

func (s *JWTAuthService) generateJWT(userID common.UserID, expiry time.Duration) (common.Token, error) {
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
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
