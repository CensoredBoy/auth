package server

import (
	l "auth/pkg/log"
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

func CEFLoggingInterceptor(logger *l.CEFLogger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		start := time.Now()
		resp, err = handler(ctx, req)
		duration := time.Since(start)

		level := l.LevelInfo
		if err != nil {
			level = l.LevelError
		}

		logger.Log(
			ctx,
			"gRPC",
			level,
			info.FullMethod,
			map[string]string{
				"duration": duration.String(),
				"status":   status.Code(err).String(),
			},
		)

		return resp, err
	}
}
func getSeverity(err error) int {
	if err == nil {
		return 3 // Успешные операции - уровень 3 (информация)
	}

	// Для gRPC ошибок используем код статуса
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument, codes.NotFound:
			return 4 // Некритичные ошибки (клиентские)
		case codes.Unauthenticated, codes.PermissionDenied:
			return 5 // Проблемы с доступом
		case codes.Internal, codes.Unavailable:
			return 7 // Серверные ошибки
		default:
			return 6 // Прочие ошибки
		}
	}

	// Для не-gRPC ошибок
	return 8 // Высокий уровень по умолчанию
}
