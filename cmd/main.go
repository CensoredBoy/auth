package main

import (
	"auth/internal/bl/hasher"
	"auth/internal/bl/jwt_service"
	"auth/internal/config"
	"auth/internal/repo/permission_repo"
	"auth/internal/repo/tokens_repo"
	"auth/internal/repo/users_repo"
	pb "auth/internal/web"
	l "auth/pkg/log"
	interceptors "auth/pkg/server"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	cefLogger := l.NewCEFLogger("auth-service")
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
	h := hasher.NewBCryptHasher(1)
	conn, err := grpc.Dial(cfg.DataProcessor.Address+":"+cfg.DataProcessor.Port, grpc.WithInsecure())
	fmt.Println(cfg.DataProcessor.Address)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Создаем репозитории
	usersRepo := users_repo.NewGrpcUserRepository(conn, cefLogger)
	permRepo := permission_repo.NewGrpcPermissionRepository(conn, cefLogger)
	tokenRepo := tokens_repo.NewTokensRedisRepo(r, cefLogger)
	jwtService := jwt_service.NewJWTAuthService([]byte(cfg.JWT.AccessSecret), []byte(cfg.JWT.RefreshSecret), tokenRepo, usersRepo, h, cefLogger)
	lis, err := net.Listen("tcp", ":"+cfg.Server.GRPCPort)
	if err != nil {
		log.Fatalf("Crashed: %v", err)
	}
	authService := pb.NewAuthServer(usersRepo, permRepo, jwtService, h, cefLogger)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptors.CEFLoggingInterceptor(cefLogger)),
	)
	pb.RegisterAuthServiceServer(grpcServer, authService)
	cefLogger.Log(
		context.Background(),
		"main",
		l.LevelInfo,
		"start",
		map[string]string{
			"message": "Server started at :" + cfg.Server.GRPCPort,
		},
	)
	if err := grpcServer.Serve(lis); err != nil {
		cefLogger.Log(
			context.Background(),
			"main",
			l.LevelError,
			"stop",
			map[string]string{
				"message": fmt.Sprintf("Server crashed: %v", err),
			},
		)
	}

}
