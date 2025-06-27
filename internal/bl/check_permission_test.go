package bl

import (
	"auth/internal/common"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockRepository struct {
	GetTeamPermissionsF         func(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error)
	GetOrganizationPermissionsF func(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error)
}

func (m *MockRepository) GetTeamPermissions(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {
	return m.GetTeamPermissionsF(ctx, userID, teamID)
}

func (m *MockRepository) GetOrganizationPermissions(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
	return m.GetOrganizationPermissionsF(ctx, userID, orgID)
}

func TestPermissionDBRepository(t *testing.T) {
	ctx := context.Background()

	t.Run("success - team permissions found", func(t *testing.T) {

		repo := &MockRepository{
			GetTeamPermissionsF: func(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {
				return []common.Permission{{Read: true, Write: true}}, nil
			},
			GetOrganizationPermissionsF: func(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
				return []common.Permission{{Read: true, Write: true}}, nil
			},
		}

		teamID := common.TeamID(1)
		orgID := common.OrgID(1)
		req := UserAccessRequest{
			UserID:         1,
			TeamID:         &teamID,
			OrganizationID: &orgID,
		}

		perm, err := CheckPermission(ctx, req, repo)

		assert.Equal(t, common.Permission{Read: true, Write: true}, perm)
		require.NoError(t, err)
	})

	t.Run("success - fallback to organization permissions", func(t *testing.T) {

		repo := &MockRepository{
			GetTeamPermissionsF: func(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {
				return []common.Permission{}, nil
			},
			GetOrganizationPermissionsF: func(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
				return []common.Permission{{Read: true, Write: true}}, nil
			},
		}

		teamID := common.TeamID(1)
		orgID := common.OrgID(1)
		req := UserAccessRequest{
			UserID:         1,
			TeamID:         &teamID,
			OrganizationID: &orgID,
		}

		perm, err := CheckPermission(ctx, req, repo)
		require.NoError(t, err)
		assert.Equal(t, common.Permission{Read: true, Write: true}, perm)

	})

	t.Run("error - no permissions found", func(t *testing.T) {
		repo := &MockRepository{
			GetTeamPermissionsF: func(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {
				return []common.Permission{}, nil
			},
			GetOrganizationPermissionsF: func(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
				return []common.Permission{}, nil
			},
		}

		req := UserAccessRequest{
			UserID:         1,
			TeamID:         nil,
			OrganizationID: nil,
		}

		perm, err := CheckPermission(ctx, req, repo)
		require.NoError(t, err)
		require.Equal(t, common.Permission{
			Read:  false,
			Write: false,
		}, perm)

	})
}
