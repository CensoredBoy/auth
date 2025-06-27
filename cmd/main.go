package main

import (
	"auth/internal/bl/hasher"
	"auth/internal/bl/jwt_service"
	"auth/internal/config"
	"auth/internal/repo/permission_repo"
	"auth/internal/repo/tokens_repo"
	"auth/internal/repo/users_repo"
	pb "auth/internal/web"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	cfg := config.Load()
	r := redis.NewClient(&redis.Options{
		Addr:         cfg.Redis.Addr,
		Username:     cfg.Redis.User,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		MaxRetries:   cfg.Redis.MaxRetries,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.Timeout,
		WriteTimeout: cfg.Redis.Timeout,
	})
	users := make(map[string]users_repo.User)
	users["admin"] = users_repo.User{
		Password: "admin",
		ID:       1,
	}
	users["test"] = users_repo.User{
		Password: "jopa",
		ID:       2,
	}
	h := hasher.NewBCryptHasher(1)
	usersRepo := users_repo.NewInMemoryUsersRepository(users)
	psqlInfo := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		cfg.Database.User, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)
	conn, err := pgx.Connect(context.Background(), psqlInfo)
	defer conn.Close(context.Background())
	tokenRepo := tokens_repo.NewTokensRedisRepo(r)
	jwtService := jwt_service.NewJWTAuthService([]byte(cfg.JWT.AccessSecret), []byte(cfg.JWT.RefreshSecret), tokenRepo, usersRepo, h)
	permRepo := permission_repo.NewPermissionRepository(conn)
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("ЕБАНУЛОСЬ: %v", err)
	}
	authService := pb.NewAuthServer(usersRepo, permRepo, jwtService, h)
	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, authService)

	log.Println("Сервер запущен на :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("СЕРВЕР ЕБНУЛСЯ: %v", err)
	}

}
