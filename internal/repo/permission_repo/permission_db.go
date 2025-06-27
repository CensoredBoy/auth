package permission_repo

import (
	"auth/internal/common"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/pgxpool"
)

var _ IPermissionRepository = (*PermissionDBRepository)(nil)

type DB interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

type PermissionDBRepository struct {
	db DB
}

func NewPermissionRepository(db DB) *PermissionDBRepository {
	return &PermissionDBRepository{db: db}
}

func (r *PermissionDBRepository) WithTx(tx pgx.Tx) *PermissionDBRepository {
	return &PermissionDBRepository{db: tx}
}

func (r *PermissionDBRepository) GetTeamPermissions(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {
	const query = `SELECT p.read, p.write FROM users_roles ur
		JOIN roles_permission_team rpt ON ur.role_id = rpt.role_id
		JOIN permissions p ON rpt.permission_id = p.id
		WHERE ur.user_id = $1 AND rpt.team_id = $2`

	rows, err := r.db.Query(ctx, query, userID, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []common.Permission
	for rows.Next() {
		var p common.Permission
		if err := rows.Scan(&p.Read, &p.Write); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}

	return perms, nil
}

func (r *PermissionDBRepository) GetOrganizationPermissions(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
	const query = `SELECT p.read, p.write FROM users_roles ur
		JOIN roles_permission_organisation rpo ON ur.role_id = rpo.role_id
		JOIN permissions p ON rpo.permission_id = p.id
		WHERE ur.user_id = $1 AND rpo.organisation_id = $2`

	rows, err := r.db.Query(ctx, query, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query organization permissions: %w", err)
	}
	defer rows.Close()

	var perms []common.Permission
	for rows.Next() {
		var p common.Permission
		if err := rows.Scan(&p.Read, &p.Write); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		perms = append(perms, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return perms, nil

}
