package permission_repo

import (
	"auth/internal/common"
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"testing"
	_ "testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres" // Вот правильный импорт
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(ctx context.Context) (*pgxpool.Pool, func(), error) {
	// 1. Запуск PostgreSQL контейнера
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("test_db"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start container: %w", err)
	}

	// 2. Получаем строку подключения с явным указанием порта
	host, err := pgContainer.Host(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get host: %w", err)
	}

	port, err := pgContainer.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get port: %w", err)
	}

	connStr := fmt.Sprintf("postgres://test:test@%s:%s/test_db?sslmode=disable", host, port.Port())

	// 3. Ждем готовности БД с таймаутом
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var pool *pgxpool.Pool
	for i := 0; i < 5; i++ {
		pool, err = pgxpool.New(ctxWithTimeout, connStr)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect after retries: %w", err)
	}

	// 4. Функция очистки
	cleanup := func() {
		pool.Close()
		if err := pgContainer.Terminate(ctx); err != nil {
			log.Printf("failed to terminate container: %v", err)
		}
	}

	// 5. Применяем миграции
	if err := initTestSchema(ctxWithTimeout, pool); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to apply migrations: %w", err)
	}

	return pool, cleanup, nil
}

func initTestSchema(ctx context.Context, pool *pgxpool.Pool) error {
	// Удаляем все таблицы если они существуют
	_, err := pool.Exec(ctx, `
        DROP TABLE IF EXISTS 
            roles_permission_team, 
            roles_permission_organisation,
            users_roles,
            permissions,
            teams,
            organizations,
            roles,
            users CASCADE;
    `)
	if err != nil {
		return fmt.Errorf("failed to clean db: %w", err)
	}

	// Создаем таблицы с правильным синтаксисом
	_, err = pool.Exec(ctx, `
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
            owner_id INTEGER REFERENCES users(id)
        );

        CREATE TABLE permissions (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(512),
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
            read BOOLEAN,
            write BOOLEAN
        );

        CREATE TABLE organizations (
            id SERIAL PRIMARY KEY,
            project_name VARCHAR(255) NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id)
        );

        CREATE TABLE teams (
            id SERIAL PRIMARY KEY,
            team_name VARCHAR(255) NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            folder VARCHAR(255),
            organization_id INTEGER NOT NULL REFERENCES organizations(id)
        );

        CREATE TABLE users_roles (
            user_id INTEGER NOT NULL REFERENCES users(id),
            role_id INTEGER NOT NULL REFERENCES roles(id),
            PRIMARY KEY (user_id, role_id)
        );

        CREATE TABLE roles_permission_organisation (
            role_id INTEGER NOT NULL REFERENCES roles(id),
            organisation_id INTEGER NOT NULL REFERENCES organizations(id),
            permission_id INTEGER NOT NULL REFERENCES permissions(id),
            PRIMARY KEY (role_id, organisation_id, permission_id)
        );

        CREATE TABLE roles_permission_team (
            role_id INTEGER NOT NULL REFERENCES roles(id),
            team_id INTEGER NOT NULL REFERENCES teams(id),
            permission_id INTEGER NOT NULL REFERENCES permissions(id),
            PRIMARY KEY (role_id, team_id, permission_id)
        );
    `)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Вставляем тестовые данные
	_, err = pool.Exec(ctx, `
        -- Пользователи
        INSERT INTO users (id, name, password) VALUES 
            (1, 'admin', 'admin123'),
            (2, 'user', 'user123');

        -- Роли
        INSERT INTO roles (id, name) VALUES 
            (1, 'admin'),
            (2, 'member');

        -- Права
        INSERT INTO permissions (id, name, read, write) VALUES
            (1, 'full_access', true, true),
            (2, 'read_only', true, false);

        -- Организации
        INSERT INTO organizations (id, project_name, owner_id) VALUES
            (1, 'Test Org', 1);

        -- Команды
        INSERT INTO teams (id, team_name, owner_id, organization_id) VALUES
            (1, 'Dev Team', 1, 1);

        -- Связи пользователь-роль
        INSERT INTO users_roles (user_id, role_id) VALUES
            (1, 1),  -- admin имеет роль admin
            (2, 2);   -- user имеет роль member

        -- Права ролей в организации
        INSERT INTO roles_permission_organisation (role_id, organisation_id, permission_id) VALUES
            (1, 1, 1),  -- admin имеет полные права в организации
            (2, 1, 2);  -- member имеет read-only в организации

        -- Права ролей в команде
        INSERT INTO roles_permission_team (role_id, team_id, permission_id) VALUES
            (1, 1, 1),  -- admin имеет полные права в команде
            (2, 1, 2);  -- member имеет read-only в команде
    `)
	if err != nil {
		return fmt.Errorf("failed to insert test data: %w", err)
	}

	return nil
}
func TestPermissionQueries(t *testing.T) {
	ctx := context.Background()
	pool, c, err := setupTestDB(ctx)
	require.NoError(t, err)
	defer pool.Close()

	t.Run("Check admin team permissions", func(t *testing.T) {
		repo := NewPermissionRepository(pool)
		teamID := common.TeamID(1)
		perm, err := repo.GetTeamPermissions(ctx, 1, teamID)

		require.NoError(t, err)
		assert.Equal(t, len(perm), 1)
		assert.Equal(t, true, perm[0].Read)
		assert.Equal(t, true, perm[0].Write) // admin имеет полные права
	})

	t.Run("Check member organization permissions", func(t *testing.T) {
		repo := NewPermissionRepository(pool)
		orgID := common.OrgID(1)
		perm, err := repo.GetOrganizationPermissions(ctx, 2, orgID)

		require.NoError(t, err)
		assert.Equal(t, len(perm), 1)
		assert.Equal(t, true, perm[0].Read)
		assert.Equal(t, false, perm[0].Write) // только чтение
	})
	t.Cleanup(func() {
		c()
	})
}

func truncateAllTables(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		TRUNCATE 
			users, roles, permissions, 
			users_roles, roles_permission_team, 
			roles_permission_organisation CASCADE;
	`)
	return err
}
