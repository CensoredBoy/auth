package permission_repo

import (
	"auth/internal/common"
	"context"
)

type IPermissionRepository interface {
	GetTeamPermissions(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error)
	GetOrganizationPermissions(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error)
}
