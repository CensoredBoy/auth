package authv1

import (
	"auth/internal/bl"
	"auth/internal/bl/hasher"
	"auth/internal/bl/jwt_service"
	"auth/internal/common"
	"auth/internal/repo/permission_repo"
	"auth/internal/repo/users_repo"
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

type AuthServer struct {
	UnimplementedAuthServiceServer
	userRepo            users_repo.IUserRepository
	permissionRepo      permission_repo.IPermissionRepository
	authService         jwt_service.ITokenService
	keycloakAuthService jwt_service.ITokenService
	h                   hasher.IHasher
}

func NewAuthServer(
	userRepo users_repo.IUserRepository,
	permissionRepo permission_repo.IPermissionRepository,
	jwtService jwt_service.ITokenService,
	h hasher.IHasher,
) *AuthServer {
	return &AuthServer{
		userRepo:       userRepo,
		permissionRepo: permissionRepo,
		authService:    jwtService,
		h:              h,
	}
}

func (s *AuthServer) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {

	user_dto := &common.User{
		Username: req.Username,
		Password: req.Password,
	}
	token, err := bl.LoginHandler(user_dto, s.authService)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to generate jwt_service: %v", err)
	}
	return &LoginResponse{
		AccessToken:  string(token.AccessToken),
		RefreshToken: string(token.RefreshToken),
		ExpiresAt:    timestamppb.New(time.Now().Add(time.Duration(token.ExpiresAt))),
	}, nil
}

func (s *AuthServer) CheckPermission(ctx context.Context, req *PermissionRequest) (*PermissionResponse, error) {
	team := common.TeamID(req.Team)
	org := common.OrgID(req.Org)
	token := req.AccessToken
	req_dto := common.UserAccessRequest{
		TeamID:         &team,
		OrganizationID: &org,
	}
	permission, err := bl.CheckPermissionHandler(ctx, req_dto, common.Token(token), s.permissionRepo, s.authService)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to get permossions: %v", err)
	}
	response := &PermissionResponse{
		Read:  permission.Read,
		Write: permission.Write,
	}

	return response, nil
}

func (s *AuthServer) Refresh(ctx context.Context, req *RefreshRequest) (*LoginResponse, error) {
	refreshToken := req.RefreshToken
	tokens, err := bl.RefreshTokenHandler(common.Token(refreshToken), s.authService)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to refresh tokens: %v", err)
	}

	return &LoginResponse{
		AccessToken:  string(tokens.AccessToken),
		RefreshToken: string(tokens.RefreshToken),
		ExpiresAt:    timestamppb.New(time.Unix(tokens.ExpiresAt, 0)),
	}, nil
}

func (s *AuthServer) LoginKeycloak(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {

	user_dto := &common.User{
		Username: req.Username,
		Password: req.Password,
	}
	if _, ok := s.userRepo.Get(user_dto); !ok {
		err := s.userRepo.CreateUser(user_dto)
		if err != nil {
			return nil, err
		}
	}
	token, err := bl.LoginHandler(user_dto, s.keycloakAuthService)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to generate jwt_service: %v", err)
	}
	return &LoginResponse{
		AccessToken:  string(token.AccessToken),
		RefreshToken: string(token.RefreshToken),
		ExpiresAt:    timestamppb.New(time.Now().Add(time.Duration(token.ExpiresAt))),
	}, nil
}

func (s *AuthServer) CheckPermissionKeycloak(ctx context.Context, req *PermissionRequest) (*PermissionResponse, error) {
	team := common.TeamID(req.Team)
	org := common.OrgID(req.Org)
	token := req.AccessToken
	req_dto := common.UserAccessRequest{
		TeamID:         &team,
		OrganizationID: &org,
	}
	permission, err := bl.CheckPermissionHandler(ctx, req_dto, common.Token(token), s.permissionRepo, s.keycloakAuthService)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to get permossions: %v", err)
	}
	response := &PermissionResponse{
		Read:  permission.Read,
		Write: permission.Write,
	}

	return response, nil
}

func (s *AuthServer) RefreshKeycloak(ctx context.Context, req *RefreshRequest) (*LoginResponse, error) {
	refreshToken := req.RefreshToken
	tokens, err := bl.RefreshTokenHandler(common.Token(refreshToken), s.keycloakAuthService)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to refresh tokens: %v", err)
	}

	return &LoginResponse{
		AccessToken:  string(tokens.AccessToken),
		RefreshToken: string(tokens.RefreshToken),
		ExpiresAt:    timestamppb.New(time.Unix(tokens.ExpiresAt, 0)),
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *LoginResponse) (*LogoutResponse, error) {
	token_dto := &common.TokenPair{
		AccessToken:  common.Token(req.AccessToken),
		RefreshToken: common.Token(req.RefreshToken),
		ExpiresAt:    0,
	}
	err := s.authService.RevokeTokens(token_dto)
	if err != nil {
		return nil, err
	}
	return &LogoutResponse{
		Ok: true,
	}, nil
}

func (s *AuthServer) LogoutKeycloak(ctx context.Context, req *LoginResponse) (*LogoutResponse, error) {
	return &LogoutResponse{
		Ok: true,
	}, nil
}
