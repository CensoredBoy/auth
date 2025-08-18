package users_repo

import (
	"auth/internal/common"
	data_processor "auth/internal/repo/proto"
	"context"
	"google.golang.org/grpc"
)

type grpcUserRepository struct {
	client data_processor.UserServiceClient
}

func NewGrpcUserRepository(conn *grpc.ClientConn) IUserRepository {
	return &grpcUserRepository{
		client: data_processor.NewUserServiceClient(conn),
	}
}

func (r *grpcUserRepository) Get(user *common.User) (string, bool) {
	resp, err := r.client.GetUserByName(context.Background(), &data_processor.GetUserByNameRequest{
		Name: user.Username,
	})
	if err != nil {
		return "", false
	}
	return resp.Password, true
}

func (r *grpcUserRepository) GetID(user *common.User) common.UserID {
	resp, err := r.client.GetUserID(context.Background(), &data_processor.GetUserIDRequest{
		User: &data_processor.User{
			Name: user.Username,
		},
	})
	if err != nil {
		return 0
	}
	return common.UserID(resp.UserId)
}

func (r *grpcUserRepository) CreateUser(user *common.User) error {
	_, err := r.client.CreateUser(context.Background(), &data_processor.CreateUserRequest{
		Name:     user.Username,
		Password: user.Password, // предполагаем, что есть поле Password
	})
	return err
}
