package permission_repo

import (
	"auth/internal/common"
	data_processor "auth/internal/repo/proto"
	logger "auth/pkg/log"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"strings"
)

type grpcPermissionRepository struct {
	client data_processor.PermissionServiceClient
	logger logger.Logger
}

func NewGrpcPermissionRepository(conn *grpc.ClientConn, l logger.Logger) IPermissionRepository {
	return &grpcPermissionRepository{
		client: data_processor.NewPermissionServiceClient(conn),
		logger: l,
	}
}

func (r *grpcPermissionRepository) GetTeamPermissions(ctx context.Context, userID common.UserID, teamID common.TeamID) ([]common.Permission, error) {

	r.logger.Log(
		context.Background(),
		"permission_grpc_repo",
		logger.LevelInfo,
		"GetTeamPermissions",
		map[string]string{},
	)
	resp, err := r.client.GetTeamPermissions(ctx, &data_processor.GetTeamPermissionsRequest{
		UserId: int32(userID),
		TeamId: int32(teamID),
	})
	if err != nil {
		r.logger.Log(
			context.Background(),
			"permission_grpc_repo",
			logger.LevelError,
			"GetTeamPermissions",
			map[string]string{"error": err.Error()},
		)
		return nil, err
	}
	var permissionStrs []string
	var permissions []common.Permission
	for _, p := range resp.Permissions {
		permissionStrs = append(permissionStrs, fmt.Sprintf("r:%t,w:%t", p.Read, p.Write))
		permissions = append(permissions, common.Permission{
			Read:  p.Read,
			Write: p.Write,
		})
	}
	r.logger.Log(
		context.Background(),
		"permission_grpc_repo",
		logger.LevelDebug,
		"GetTeamPermissions",
		map[string]string{
			"permissions": strings.Join(permissionStrs, ";"),
		},
	)
	r.logger.Log(
		context.Background(),
		"permission_grpc_repo",
		logger.LevelInfo,
		"GetTeamPermissions",
		map[string]string{
			"count": fmt.Sprintf("%d", len(permissions)),
		},
	)
	return permissions, nil
}

func (r *grpcPermissionRepository) GetOrganizationPermissions(ctx context.Context, userID common.UserID, orgID common.OrgID) ([]common.Permission, error) {
	r.logger.Log(
		context.Background(),
		"permission_grpc_repo",
		logger.LevelInfo,
		"GetOrganizationPermissions",
		map[string]string{},
	)
	resp, err := r.client.GetOrganizationPermissions(ctx, &data_processor.GetOrganizationPermissionsRequest{
		UserId: int32(userID),
		OrgId:  int32(orgID),
	})
	if err != nil {
		r.logger.Log(
			context.Background(),
			"permission_grpc_repo",
			logger.LevelError,
			"GetOrganizationPermissions",
			map[string]string{"error": err.Error()},
		)
		return nil, err
	}
	var permissionStrs []string
	var permissions []common.Permission
	for _, p := range resp.Permissions {
		permissionStrs = append(permissionStrs, fmt.Sprintf("r:%t,w:%t", p.Read, p.Write))
		permissions = append(permissions, common.Permission{
			Read:  p.Read,
			Write: p.Write,
		})
	}
	r.logger.Log(
		context.Background(),
		"permission_grpc_repo",
		logger.LevelDebug,
		"GetOrganizationPermissions",
		map[string]string{
			"permissions": strings.Join(permissionStrs, ";"),
		},
	)
	r.logger.Log(
		context.Background(),
		"permission_grpc_repo",
		logger.LevelInfo,
		"GetOrganizationPermissions",
		map[string]string{
			"count": fmt.Sprintf("%d", len(permissions)),
		},
	)
	return permissions, nil
}
