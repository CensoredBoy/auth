package main

import (
	"auth/internal/bl/hasher"
	"auth/internal/bl/jwt_service"
	"auth/internal/common"
	"auth/internal/repo/permission_repo"
	"auth/internal/repo/tokens_repo"
	"auth/internal/repo/users_repo"
	proto "auth/internal/web"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"testing"
	"time"
	_ "time"

	_ "github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const (
	postgresUser     = "test"
	postgresPassword = "test"
	postgresDB       = "test"
)

type IntegrationTestSuite struct {
	suite.Suite
	pgContainer    testcontainers.Container
	redisContainer testcontainers.Container
	db             *pgx.Conn
	grpcServer     *grpc.Server
	client         proto.AuthServiceClient
	conn           *grpc.ClientConn
}

func (s *IntegrationTestSuite) SetupSuite() {
	ctx := context.Background()
	reqR := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine", // или другая версия
		ExposedPorts: []string{"6379/tcp"},
		Env: map[string]string{
			"REDIS_PASSWORD": "ebalmamy",
			// Для ACL (если нужно):
			// "REDIS_ACL_USERNAME": redisUser,
			// "REDIS_ACL_PASSWORD": redisPassword,
		},
		WaitingFor: wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
	}

	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqR,
		Started:          true,
	})
	require.NoError(s.T(), err)
	s.redisContainer = redisContainer
	fmt.Println("Redis container running:", s.redisContainer.IsRunning())
	logs, err := s.redisContainer.Logs(context.Background())
	require.NoError(s.T(), err)
	fmt.Println("Redis logs:", logs)

	hostRedis, err := redisContainer.Host(ctx)
	require.NoError(s.T(), err)
	portRedis, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(s.T(), err)

	redisAddr := hostRedis + ":" + portRedis.Port()

	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	require.NotNil(s.T(), rdb)
	// 1. Запускаем Postgres в контейнере
	req := testcontainers.ContainerRequest{
		Image:        "postgres:15-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     postgresUser,
			"POSTGRES_PASSWORD": postgresPassword,
			"POSTGRES_DB":       postgresDB,
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		).WithStartupTimeout(2 * time.Minute),
	}
	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(s.T(), err)
	s.pgContainer = pgContainer
	fmt.Println("Postgres container running:", s.pgContainer.IsRunning())

	// 2. Получаем URL для подключения к Postgres
	pgHost, err := pgContainer.Host(ctx)
	require.NoError(s.T(), err)
	pgPort, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(s.T(), err)
	l, err := s.pgContainer.Logs(context.Background())
	require.NoError(s.T(), err)
	fmt.Println("Redis logs:", l)
	pgURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, pgHost, pgPort.Port(), postgresDB)

	// 3. Подключаемся к БД
	connPgx, err := pgx.Connect(ctx, pgURL)

	require.NotNil(s.T(), connPgx)
	require.NoError(s.T(), connPgx.Ping(ctx), "Postgres ping failed")

	s.db = connPgx

	// 4. Мигрируем БД (если используешь миграции)
	_, err = connPgx.Exec(ctx, `
		CREATE TABLE users (
                       id SERIAL PRIMARY KEY,
                       name VARCHAR(255) NOT NULL,
                       password VARCHAR(255) NOT NULL
);

CREATE TABLE roles (
                       id SERIAL PRIMARY KEY,
                       name VARCHAR(255),
                       description VARCHAR(512),
                       is_active BOOLEAN DEFAULT true,
                       created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                       updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                       owner_id INTEGER,
                       FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE permissions (
                             id SERIAL PRIMARY KEY,
                             name VARCHAR(255) NOT NULL,
                             description VARCHAR(512),
                             created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                             updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                             read BOOLEAN DEFAULT false,
                             write BOOLEAN DEFAULT false
);

CREATE TABLE organizations (
                               id SERIAL PRIMARY KEY,
                               project_name VARCHAR(255) NOT NULL,
                               owner_id INTEGER NOT NULL,
                               FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE teams (
                       id SERIAL PRIMARY KEY,
                       team_name VARCHAR(255) NOT NULL,
                       owner_id INTEGER NOT NULL,
                       folder VARCHAR(255),
                       organization_id INTEGER NOT NULL,
                       FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                       FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE users_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE roles_permission_organisation (
    role_id INTEGER NOT NULL,
    organisation_id INTEGER NOT NULL,
    permission_id INTEGER UNIQUE NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (organisation_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
CREATE TABLE roles_permission_team (
   role_id INTEGER NOT NULL,
   team_id INTEGER NOT NULL,
   permission_id INTEGER UNIQUE NOT NULL,
   FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
   FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
   FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE applications (
                              id SERIAL PRIMARY KEY,
                              name VARCHAR(255) NOT NULL,
                              description VARCHAR(512),
                            team_id INTEGER NOT NULL,
                              FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL

);

CREATE TABLE versions (
                                      id SERIAL PRIMARY KEY,
                                      application_id INTEGER NOT NULL,
                                      version VARCHAR(50) NOT NULL,
                                      FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

CREATE TABLE scans (
                       id SERIAL PRIMARY KEY,
                       scan_date DATE NOT NULL DEFAULT CURRENT_DATE,
                       version_id INTEGER NOT NULL,
                       FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE CASCADE
);

CREATE TABLE scan_info (
                           id SERIAL PRIMARY KEY,
                           scan_id INTEGER NOT NULL,
                           FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE scan_rules (
                            id SERIAL PRIMARY KEY,
                            application_id INTEGER NOT NULL,
                            team_id INTEGER NOT NULL,
                            organization_id INTEGER NOT NULL,
                            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
                            FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

	`)
	require.NoError(s.T(), err)
	h := hasher.NewBCryptHasher(1)
	permRepo := permission_repo.NewPermissionRepository(connPgx)
	// 5. Запускаем gRPC-сервер
	repo := tokens_repo.NewTokensRedisRepo(rdb)
	m := make(map[string]users_repo.User)
	keks := common.User{
		Username: "admin",
		Password: "admin",
	}
	keks1 := common.User{
		Username: "testuser",
		Password: "admin",
	}
	pwd, _ := h.GenerateHash(&keks)
	pwd1, _ := h.GenerateHash(&keks1)
	m["admin"] = users_repo.User{
		ID:       1,
		Password: pwd,
	}
	m["testuser"] = users_repo.User{
		ID:       2,
		Password: pwd1,
	}
	usersRepo := users_repo.NewInMemoryUsersRepository(m)
	jwtService := jwt_service.NewJWTAuthService(
		[]byte("test-access-secret"),
		[]byte("test-refresh-secret"),
		repo,
		usersRepo,
		h,
	)

	lis := bufconn.Listen(1024 * 1024)
	s.grpcServer = grpc.NewServer()
	proto.RegisterAuthServiceServer(s.grpcServer, proto.NewAuthServer(usersRepo, permRepo, jwtService, h))

	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			panic(err)
		}
	}()

	// 6. Подключаем клиент
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(s.T(), err)
	s.conn = conn
	s.client = proto.NewAuthServiceClient(conn)
}
func (s *IntegrationTestSuite) TestLogin_Success() {
	ctx := context.Background()

	resp, err := s.client.Login(ctx, &proto.LoginRequest{
		Username: "admin",
		Password: "admin",
	})

	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), resp.AccessToken)
	require.NotEmpty(s.T(), resp.RefreshToken)
	require.True(s.T(), resp.ExpiresAt.AsTime().After(time.Now()))
}

func (s *IntegrationTestSuite) TestLogin_InvalidCredentials() {
	ctx := context.Background()

	_, err := s.client.Login(ctx, &proto.LoginRequest{
		Username: "admin",
		Password: "wrongpassword",
	})

	require.Error(s.T(), err)
	grpcErr, ok := status.FromError(err)
	require.True(s.T(), ok)
	require.Equal(s.T(), codes.Unauthenticated, grpcErr.Code())
}

func (s *IntegrationTestSuite) TestRefresh_Success() {
	ctx := context.Background()

	// Сначала логинимся чтобы получить refresh token
	loginResp, err := s.client.Login(ctx, &proto.LoginRequest{
		Username: "admin",
		Password: "admin",
	})
	require.NoError(s.T(), err)

	// Пробуем обновить токен
	refreshResp, err := s.client.Refresh(ctx, &proto.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
	})

	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), refreshResp.AccessToken)
	require.NotEmpty(s.T(), refreshResp.RefreshToken)
	require.True(s.T(), refreshResp.ExpiresAt.AsTime().After(time.Now()))

	// Проверяем что новый refresh токен отличается от старого
	require.NotEqual(s.T(), loginResp.RefreshToken, refreshResp.RefreshToken)
}

func (s *IntegrationTestSuite) TestRefresh_InvalidToken() {
	ctx := context.Background()

	_, err := s.client.Refresh(ctx, &proto.RefreshRequest{
		RefreshToken: "invalid.token.here",
	})

	require.Error(s.T(), err)
	grpcErr, ok := status.FromError(err)
	require.True(s.T(), ok)
	require.Equal(s.T(), codes.Unauthenticated, grpcErr.Code())
}

func (s *IntegrationTestSuite) TestCheckPermission_WithoutToken() {
	ctx := context.Background()

	_, err := s.client.CheckPermission(ctx, &proto.PermissionRequest{
		AccessToken: "",
		Org:         1,
		Team:        1,
	})

	require.Error(s.T(), err)
	grpcErr, ok := status.FromError(err)
	require.True(s.T(), ok)
	require.Equal(s.T(), codes.Unauthenticated, grpcErr.Code())
}

func (s *IntegrationTestSuite) TestCheckPermission_WithInvalidToken() {
	ctx := context.Background()

	resp, err := s.client.CheckPermission(ctx, &proto.PermissionRequest{
		AccessToken: "invalid.token.here",
		Org:         1,
		Team:        1,
	})
	fmt.Println(resp)
	fmt.Println(err)
	require.Error(s.T(), err)
	grpcErr, ok := status.FromError(err)
	require.True(s.T(), ok)
	require.Equal(s.T(), codes.Unauthenticated, grpcErr.Code())
}

func (s *IntegrationTestSuite) TestCheckPermission_WithValidToken() {
	ctx := context.Background()

	// Сначала логинимся чтобы получить токен
	loginResp, err := s.client.Login(ctx, &proto.LoginRequest{
		Username: "testuser",
		Password: "admin",
	})
	require.NoError(s.T(), err)

	// Проверяем permissions
	permResp, err := s.client.CheckPermission(ctx, &proto.PermissionRequest{
		AccessToken: loginResp.AccessToken,
		Org:         2,
		Team:        1,
	})
	fmt.Println(permResp.Read)
	fmt.Println(permResp.Write)
	require.NoError(s.T(), err)
	// Так как в тестовой БД нет пермишенов, ожидаем false
	require.True(s.T(), permResp.Read)
	require.True(s.T(), permResp.Write)
}
func (s *IntegrationTestSuite) TestCheckPermission_WithActualPermissions() {
	ctx := context.Background()

	// Создаем тестовые данные в БД
	_, err := s.db.Exec(ctx, `
INSERT INTO users (id, name, password) VALUES 
    (1, 'admin', 'hash'),
    (2, 'testuser', 'hash');
INSERT INTO organizations (id, project_name, owner_id) VALUES (1, 'test', 1);
INSERT INTO organizations (id, project_name, owner_id) VALUES (2, 'test', 2);


INSERT INTO permissions (id, name, read, write) VALUES (1, 'test', true, false);
INSERT INTO permissions (id, name, read, write) VALUES (2, 'test1', true, true);
INSERT INTO organizations (id, project_name, owner_id) VALUES (3, 'test', 1);
INSERT INTO teams (id, team_name, owner_id, organization_id) VALUES (1, 'test', 1, 1);
INSERT INTO roles (id, name) VALUES (1, 'test');
INSERT INTO roles (id, name) VALUES (2, 'test1');
INSERT INTO users_roles (user_id, role_id) VALUES (1, 1);
INSERT INTO users_roles (user_id, role_id) VALUES (2, 2);
INSERT INTO roles_permission_organisation (role_id, organisation_id, permission_id) VALUES (1, 1, 1);
INSERT INTO roles_permission_organisation (role_id, organisation_id, permission_id) VALUES (2, 2, 2);
    `)
	require.NoError(s.T(), err)

	// Логинимся
	loginResp, err := s.client.Login(ctx, &proto.LoginRequest{
		Username: "admin",
		Password: "admin",
	})
	require.NoError(s.T(), err)

	// Проверяем permissions
	permResp, err := s.client.CheckPermission(ctx, &proto.PermissionRequest{
		AccessToken: loginResp.AccessToken,
		Org:         1,
		Team:        1,
	})

	require.NoError(s.T(), err)
	require.True(s.T(), permResp.Read)
	require.False(s.T(), permResp.Write)
}
func (s *IntegrationTestSuite) TearDownSuite() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
	if s.db != nil {
		_ = s.db.Close(context.Background())
	}
	if s.pgContainer != nil {
		_ = s.pgContainer.Terminate(context.Background())
	}
	if s.redisContainer != nil {
		_ = s.redisContainer.Terminate(context.Background())
	}
}

func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}
