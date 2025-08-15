package permission_repo

import (
	"auth/internal/common"
	data_processor "auth/internal/repo/proto"
	"context"
	"google.golang.org/grpc"
)

type grpcPermissionRepository struct {
	client data_processor.PermissionServiceClient
}

func NewGrpcPermissionRepository(conn *grpc.ClientConn) IPermissionRepository {
	return &grpcPermissionRepository{
		client: data_processor.NewPermissionServiceClient(conn),
	}
}

func (r *grpcPermissionRepository) GetTeamPermissions(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {
	resp, err := r.client.GetTeamPermissions(ctx, &data_processor.GetTeamPermissionsRequest{
		UserId: int32(userID),
		TeamId: int32(teamID),
	})
	if err != nil {
		return nil, err
	}

	var permissions []common.Permission
	for _, p := range resp.Permissions {
		permissions = append(permissions, common.Permission{
			Read:  p.Read,
			Write: p.Write,
		})
	}
	return permissions, nil
}

func (r *grpcPermissionRepository) GetOrganizationPermissions(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
	resp, err := r.client.GetOrganizationPermissions(ctx, &data_processor.GetOrganizationPermissionsRequest{
		UserId: int32(userID),
		OrgId:  int32(orgID),
	})
	if err != nil {
		return nil, err
	}

	var permissions []common.Permission
	for _, p := range resp.Permissions {
		permissions = append(permissions, common.Permission{
			Read:  p.Read,
			Write: p.Write,
		})
	}
	return permissions, nil
}
