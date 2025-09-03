package users_repo

import (
	"auth/internal/common"
	data_processor "auth/internal/repo/proto"
	logger "auth/pkg/log"
	"context"
	"google.golang.org/grpc"
)

type grpcUserRepository struct {
	client data_processor.UserServiceClient
	logger logger.Logger
}

func NewGrpcUserRepository(conn *grpc.ClientConn, l logger.Logger) IUserRepository {
	return &grpcUserRepository{
		client: data_processor.NewUserServiceClient(conn),
		logger: l,
	}
}

func (r *grpcUserRepository) Get(user *common.User) (string, bool) {
	r.logger.Log(
		context.Background(),
		"users_grpc_repo",
		logger.LevelInfo,
		"GetUser",
		map[string]string{"username": user.Username},
	)
	resp, err := r.client.GetUserByName(context.Background(), &data_processor.GetUserByNameRequest{
		Name: user.Username,
	})
	if err != nil {
		r.logger.Log(
			context.Background(),
			"users_grpc_repo",
			logger.LevelError,
			"GetUser",
			map[string]string{"error": err.Error()},
		)
		return "", false
	}
	return resp.Password, true
}

func (r *grpcUserRepository) GetID(user *common.User) common.UserID {
	r.logger.Log(
		context.Background(),
		"users_grpc_repo",
		logger.LevelInfo,
		"GetUserId",
		map[string]string{"username": user.Username},
	)
	resp, err := r.client.GetUserID(context.Background(), &data_processor.GetUserIDRequest{
		User: &data_processor.User{
			Name: user.Username,
		},
	})
	if err != nil {
		r.logger.Log(
			context.Background(),
			"users_grpc_repo",
			logger.LevelError,
			"GetUserId",
			map[string]string{"error": err.Error()},
		)
		return 0
	}
	return common.UserID(resp.UserId)
}

func (r *grpcUserRepository) CreateUser(user *common.User) error {
	r.logger.Log(
		context.Background(),
		"users_grpc_repo",
		logger.LevelInfo,
		"CreateUser",
		map[string]string{"username": user.Username},
	)
	_, err := r.client.CreateUser(context.Background(), &data_processor.CreateUserRequest{
		Name:     user.Username,
		Password: user.Password, // предполагаем, что есть поле Password
	})
	if err != nil {
		r.logger.Log(
			context.Background(),
			"users_grpc_repo",
			logger.LevelError,
			"CreateUser",
			map[string]string{"error": err.Error()},
		)
	}
	return err
}
