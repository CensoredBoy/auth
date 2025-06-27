package bl

import (
	"auth/internal/bl/jwt_service"
	"auth/internal/common"
	"auth/internal/repo/permission_repo"
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
)

type UserAccessRequest struct {
	UserID         common.UserID
	TeamID         *common.TeamID
	OrganizationID *common.OrgID
}

func CheckPermissionHandler(ctx context.Context, req common.UserAccessRequest, token common.Token, perm_repo permission_repo.IPermissionRepository, auth jwt_service.ITokenService) (common.Permission, error) {
	userID, err := auth.ValidateAccessToken(token)
	if err != nil {
		return common.Permission{}, err
	}
	request := UserAccessRequest{
		UserID:         *userID,
		TeamID:         req.TeamID,
		OrganizationID: req.OrganizationID,
	}
	return CheckPermission(ctx, request, perm_repo)
}

func CheckPermission(ctx context.Context, req UserAccessRequest, perm_repo permission_repo.IPermissionRepository) (common.Permission, error) {
	var perm common.Permission
	if req.OrganizationID != nil {
		perms, err := perm_repo.GetOrganizationPermissions(ctx, req.UserID, *req.OrganizationID)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return common.Permission{}, fmt.Errorf("failed to get org permissions: %w", err)
			}
		}
		perm = resolveConflictingPermissions(perms)

	}
	if req.TeamID != nil {
		perms, err := perm_repo.GetTeamPermissions(ctx, req.UserID, *req.TeamID)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return common.Permission{}, fmt.Errorf("failed to get team permissions: %w", err)
			} else {
				perms = append(perms, common.Permission{
					Read:  true,
					Write: true,
				})
			}
		}
		perms = append(perms, perm)
		perm = resolveConflictingPermissions(perms)
		return common.Permission{
			Read:  perm.Read,
			Write: perm.Write,
		}, nil

	}

	return common.Permission{
		Read:  perm.Read,
		Write: perm.Write,
	}, nil
}

func resolveConflictingPermissions(perms []common.Permission) common.Permission {
	var result common.Permission
	if len(perms) == 0 {
		result = common.Permission{Read: false, Write: false}
	} else {
		result = common.Permission{Read: true, Write: true}
	}

	for _, p := range perms {
		if !p.Read {
			result.Read = false
		}
		if !p.Write {
			result.Write = false
		}
	}

	return result
}
