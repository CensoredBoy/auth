package jwt_service

import (
	"auth/internal/common"
	"auth/internal/repo/users_repo"
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

var _ ITokenService = (*KeycloakTokenService)(nil)

type KeycloakTokenService struct {
	provider *oidc.Provider
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
	userRepo users_repo.IUserRepository
}

func NewKeycloakTokenService(url, clientID, clientSecret string, scopes []string) *KeycloakTokenService {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, url)
	if err != nil {
		panic(err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	return &KeycloakTokenService{
		provider: provider,
		config:   oauth2Config,
		verifier: verifier,
	}
}
func (k KeycloakTokenService) GenerateTokens(user *common.User) (*common.TokenPair, error) {
	ctx := context.Background()
	token, err := k.config.PasswordCredentialsToken(ctx, user.Username, user.Password)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
	}

	return &common.TokenPair{
		AccessToken:  common.Token(token.AccessToken),
		RefreshToken: common.Token(token.RefreshToken),
		ExpiresAt:    int64(token.Expiry.Sub(time.Now()).Seconds()),
	}, nil
}

func (k KeycloakTokenService) ValidateAccessToken(tokenString common.Token) (*common.UserID, error) {
	ctx := context.Background()
	_, err := k.verifier.Verify(ctx, string(tokenString))
	if err != nil {
		return nil, err
	}
	var claims struct {
		Username string `json:"preferred_username"`
	}
	// Дополнительно можно извлечь claims
	token, err := k.verifier.Verify(ctx, string(tokenString))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	if err := token.Claims(&claims); err != nil {
		return nil, err
	} else {
		user := common.User{
			Username: claims.Username,
			Password: "",
		}
		id := k.userRepo.GetID(&user)
		return &id, nil
	}
}

func (k KeycloakTokenService) RefreshTokens(refreshToken common.Token) (*common.TokenPair, error) {
	ctx := context.Background()
	token := &oauth2.Token{
		RefreshToken: string(refreshToken),
		Expiry:       time.Now().Add(-time.Hour), // Имитация истёкшего токена
	}

	newToken, err := k.config.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid refresh token")
	}

	return &common.TokenPair{
		AccessToken:  common.Token(newToken.AccessToken),
		RefreshToken: common.Token(newToken.RefreshToken),
		ExpiresAt:    int64(newToken.Expiry.Sub(time.Now()).Seconds()),
	}, nil
}

func (k KeycloakTokenService) RevokeTokens(tokens *common.TokenPair) error {
	return nil
}
