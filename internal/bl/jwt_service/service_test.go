package jwt_service

import (
	"auth/internal/bl/hasher"
	"auth/internal/common"
	"auth/internal/repo/users_repo"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// MockRefreshTokenRepo - мок репозитория refresh-токенов
type MockRefreshTokenRepo struct {
	tokens map[common.Token]*common.RefreshTokenData
}

func NewMockRefreshTokenRepo() *MockRefreshTokenRepo {
	return &MockRefreshTokenRepo{
		tokens: make(map[common.Token]*common.RefreshTokenData),
	}
}

func (m *MockRefreshTokenRepo) SaveRefreshToken(ctx context.Context, userID common.UserID, token common.Token, expiry time.Duration) error {
	m.tokens[token] = &common.RefreshTokenData{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(expiry),
		Used:      false,
	}
	return nil
}

func (m *MockRefreshTokenRepo) GetRefreshToken(ctx context.Context, token common.Token) (*common.RefreshTokenData, error) {
	if data, ok := m.tokens[token]; ok {
		return data, nil
	}
	return nil, errors.New("token not found")
}

func (m *MockRefreshTokenRepo) MarkRefreshTokenUsed(ctx context.Context, token common.Token) error {
	if data, ok := m.tokens[token]; ok {
		data.Used = true
		return nil
	}
	return errors.New("token not found")
}

func TestJWTAuthService(t *testing.T) {
	// Настройка тестов
	accessSecret := []byte("test-access-secret")
	refreshSecret := []byte("test-refresh-secret")
	mockRepo := NewMockRefreshTokenRepo()
	h := hasher.NewBCryptHasher(1)
	m := make(map[string]users_repo.User)
	keks := common.User{
		Username: "admin",
		Password: "admin",
	}
	pwd, _ := h.GenerateHash(&keks)
	m["admin"] = users_repo.User{
		ID:       1,
		Password: pwd,
	}
	usersRepo := users_repo.NewInMemoryUsersRepository(m)
	service := NewJWTAuthService(accessSecret, refreshSecret, mockRepo, usersRepo, h)

	t.Run("GenerateTokens - успешная генерация", func(t *testing.T) {
		tokenPair, err := service.GenerateTokens(&keks)
		if err != nil {
			t.Fatalf("GenerateTokens failed: %v", err)
		}

		if tokenPair.AccessToken == "" {
			t.Error("AccessToken should not be empty")
		}

		if tokenPair.RefreshToken == "" {
			t.Error("RefreshToken should not be empty")
		}

	})

	t.Run("ValidateAccessToken - валидный токен", func(t *testing.T) {
		userID := common.UserID(1)
		tokenPair, _ := service.GenerateTokens(&keks)

		subject, err := service.ValidateAccessToken(tokenPair.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken failed: %v", err)
		}

		if *subject != userID {
			t.Errorf("Expected userID %d, got %d", userID, *subject)
		}
	})

	t.Run("ValidateAccessToken - просроченный токен", func(t *testing.T) {
		// Генерируем токен с отрицательным сроком жизни
		expiredToken, _ := service.generateJWT(789, -time.Hour)

		_, err := service.ValidateAccessToken(expiredToken)
		if err == nil {
			t.Error("Expected error for expired token")
		} else if err.Error() != "token expired" {
			t.Errorf("Expected 'token expired' error, got: %v", err)
		}
	})

	t.Run("ValidateAccessToken - неверный формат токена", func(t *testing.T) {
		_, err := service.ValidateAccessToken("invalid.token.here")
		if err == nil {
			t.Error("Expected error for invalid token format")
		} else if err.Error() != "invalid token format" {
			t.Errorf("Expected 'invalid token format' error, got: %v", err)
		}
	})

	t.Run("ValidateRefreshToken - валидный токен", func(t *testing.T) {
		userID := common.UserID(1)
		tokenPair, _ := service.GenerateTokens(&keks)

		tokenData, err := service.ValidateRefreshToken(tokenPair.RefreshToken)
		if err != nil {
			t.Fatalf("ValidateRefreshToken failed: %v", err)
		}

		if tokenData.UserID != userID {
			t.Errorf("Expected userID %d, got %d", userID, tokenData.UserID)
		}
	})

	t.Run("ValidateRefreshToken - несуществующий токен", func(t *testing.T) {
		_, err := service.ValidateRefreshToken("nonexistenttoken1234567890123456")
		if err == nil {
			t.Error("Expected error for non-existent token")
		}
	})

	t.Run("RefreshTokens - успешное обновление", func(t *testing.T) {
		tokenPair, _ := service.GenerateTokens(&keks)

		newTokenPair, err := service.RefreshTokens(tokenPair.RefreshToken)
		if err != nil {
			t.Fatalf("RefreshTokens failed: %v", err)
		}

		if newTokenPair.AccessToken == tokenPair.AccessToken {
			t.Error("AccessToken should be renewed")
		}

		if newTokenPair.RefreshToken == tokenPair.RefreshToken {
			t.Error("RefreshToken should be renewed")
		}
	})

	t.Run("RevokeTokens - валидный токен", func(t *testing.T) {
		tokenPair, _ := service.GenerateTokens(&keks)

		err := service.RevokeTokens(tokenPair)
		if err != nil {
			t.Fatalf("RevokeTokens failed: %v", err)
		}
		_, err = service.RefreshTokens(tokenPair.RefreshToken)
		if err == nil {
			t.Fatalf("RefreshTokens failed: %v", err)
		}
		fmt.Println(err)
	})

	t.Run("RefreshTokens - повторное использование токена", func(t *testing.T) {
		tokenPair, _ := service.GenerateTokens(&keks)

		// Первое использование
		_, _ = service.RefreshTokens(tokenPair.RefreshToken)

		// Попытка повторного использования
		_, err := service.RefreshTokens(tokenPair.RefreshToken)
		if err == nil {
			t.Error("Expected error for already used token")
		} else if err.Error() != "invalid refresh token: token already used" {
			t.Errorf("Expected 'token already used' error, got: %v", err)
		}
	})
}
