// service/jwt.go
package service

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "time"

    "auth-service/internal/config"
    "auth-service/internal/models"
    // "auth-service/internal/rbac"
    "auth-service/internal/repository/postgres"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

type JWTService struct {
    config      *config.Config
    companyRepo postgres.CompanyRepository
    adminRepo   postgres.AdminRepository  // Add this
    logger      *zap.Logger
}

func NewJWTService(
    cfg *config.Config, 
    companyRepo postgres.CompanyRepository, 
    adminRepo postgres.AdminRepository,  // Add this
    logger *zap.Logger,
) *JWTService {
    return &JWTService{
        config:      cfg,
        companyRepo: companyRepo,
        adminRepo:   adminRepo,  // Add this
        logger:      logger,
    }
}
type CreateAccessTokenRequest struct {
    UserID         string
    Role           string    // Role string instead of mask
    DeviceID       string
    SessionType    string
    CompanyID      string
    IPAddress      string
    PermissionMask []uint64
}

// Update CreateAccessToken to handle admin permissions better
func (s *JWTService) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (string, string, error) {
    if req.UserID == "" {
        return "", "", fmt.Errorf("user ID is required")
    }
    if req.DeviceID == "" {
        return "", "", fmt.Errorf("device ID is required")
    }
    if req.SessionType == "" {
        return "", "", fmt.Errorf("session type is required")
    }
    if req.Role == "" {
        return "", "", fmt.Errorf("role is required")
    }

    jti := uuid.NewString()
    now := time.Now()
    
    var permissionMask []uint64
    
    // Handle admin sessions
    if req.SessionType == "admin" {
        adminID, err := uuid.Parse(req.UserID)
        if err != nil {
            return "", "", fmt.Errorf("invalid admin ID format: %w", err)
        }
        
        // Get admin permission mask from repository
        permissionMask, err = s.adminRepo.GetAdminPermissionBitmask(ctx, adminID)
        if err != nil {
            s.logger.Warn("Failed to get admin permission mask, using full access",
                zap.String("admin_id", req.UserID),
                zap.Error(err))
            permissionMask = models.CreateFullPermissionMask()
        }
        
        // Log admin session details
        s.logger.Info("🔐 ADMIN session token created",
            zap.String("admin_id", req.UserID),
            zap.String("role", req.Role),
            zap.Int("mask_segments", len(permissionMask)),
            zap.Any("permission_mask", permissionMask))
            
    } else {
        // Handle user sessions (existing logic)
        userID, err := uuid.Parse(req.UserID)
        if err != nil {
            return "", "", fmt.Errorf("invalid user ID format: %w", err)
        }
        if req.CompanyID == "" {
            return "", "", fmt.Errorf("company ID is required for user sessions")
        }
        companyID, err := uuid.Parse(req.CompanyID)
        if err != nil {
            return "", "", fmt.Errorf("invalid company ID format: %w", err)
        }

        s.logger.Info("🔍 Fetching USER permission bitmask",
            zap.String("user_id", req.UserID),
            zap.String("company_id", req.CompanyID),
            zap.String("session_type", req.SessionType),
            zap.String("role", req.Role))
            
        mask, err := s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
        if err != nil {
            s.logger.Warn("⚠️ Failed to get user permission mask, using empty mask",
                zap.String("user_id", req.UserID),
                zap.String("company_id", req.CompanyID),
                zap.Error(err))
            permissionMask = []uint64{0, 0, 0, 0}
        } else {
            permissionMask = mask
            s.logger.Info("✅ User permission mask retrieved",
                zap.String("user_id", req.UserID),
                zap.String("company_id", req.CompanyID),
                zap.Int("mask_segments", len(permissionMask)))
        }
    }

    claims := &models.JWTClaims{
        UserID:         req.UserID,
        Role:           req.Role,
        DeviceID:       req.DeviceID,
        SessionType:    req.SessionType,
        CompanyID:      req.CompanyID,
        JTI:            jti,
        IssuedAt:       now.Unix(),
        ExpiresAt:      now.Add(s.config.JWT.AccessTTL).Unix(),
        PermissionMask: permissionMask,
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := token.SignedString([]byte(s.config.JWT.Secret))
    if err != nil {
        return "", "", fmt.Errorf("failed to sign token: %w", err)
    }

    s.logger.Info("🎫 JWT access token created",
        zap.String("user_id", req.UserID),
        zap.String("session_type", req.SessionType),
        zap.String("company_id", req.CompanyID),
        zap.String("role", req.Role),
        zap.String("jti", jti),
        zap.Int64("expires_at", claims.ExpiresAt))

    return signed, jti, nil
}
// ValidateAccessToken validates and parses JWT access token (signature only)
func (s *JWTService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
    if tokenStr == "" {
        return nil, fmt.Errorf("token string is empty")
    }

    token, err := jwt.ParseWithClaims(tokenStr, &models.JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return []byte(s.config.JWT.Secret), nil
    })

    if err != nil {
        s.logger.Warn("JWT token parse failed", zap.Error(err))
        return nil, fmt.Errorf("token parse error: %w", err)
    }

    if !token.Valid {
        return nil, fmt.Errorf("invalid token")
    }

    claims, ok := token.Claims.(*models.JWTClaims)
    if !ok {
        return nil, fmt.Errorf("invalid token claims")
    }

    // Validate required claim fields
    if claims.UserID == "" {
        return nil, fmt.Errorf("token missing user ID")
    }
    if claims.SessionType == "" {
        return nil, fmt.Errorf("token missing session type")
    }
    if claims.Role == "" {
        return nil, fmt.Errorf("token missing role")
    }

    // For non-admin sessions, validate CompanyID exists
    if claims.SessionType != "admin" && claims.CompanyID == "" {
        return nil, fmt.Errorf("non-admin token missing company ID")
    }

    s.logger.Debug("JWT token validated successfully",
        zap.String("user_id", claims.UserID),
        zap.String("session_type", claims.SessionType),
        zap.String("role", claims.Role),
        zap.String("jti", claims.JTI))

    return claims, nil
}

// GenerateRefreshToken generates opaque refresh token
func (s *JWTService) GenerateRefreshToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("failed to generate random token: %w", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateTokenPair creates both access and refresh tokens
func (s *JWTService) CreateTokenPair(ctx context.Context, req *CreateAccessTokenRequest) (*models.TokenPairResponse, error) {
    accessToken, _, err := s.CreateAccessToken(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("failed to create access token: %w", err)
    }

    refreshToken, err := s.GenerateRefreshToken()
    if err != nil {
        return nil, fmt.Errorf("failed to generate refresh token: %w", err)
    }

    return &models.TokenPairResponse{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    int(s.config.JWT.AccessTTL.Seconds()),
        TokenType:    "Bearer",
    }, nil
}

// VerifyTokenExpiration checks if token is expired (helper method)
func (s *JWTService) VerifyTokenExpiration(claims *models.JWTClaims) bool {
    now := time.Now().Unix()
    return claims.ExpiresAt > now
}
// // internal/service/jwt_service.go
// package service

// import (
// 	"context"
// 	"crypto/rand"
// 	"encoding/hex"
// 	"fmt"
// 	"time"

// 	"auth-service/internal/config"
// 	"auth-service/internal/models"
// 	"auth-service/internal/rbac"
// 	"auth-service/internal/repository/postgres"

// 	"github.com/golang-jwt/jwt/v5"
// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// type JWTService struct {
// 	config      *config.Config
// 	companyRepo postgres.CompanyRepository
// 	logger      *zap.Logger
// }

// func NewJWTService(cfg *config.Config, companyRepo postgres.CompanyRepository, logger *zap.Logger) *JWTService {
// 	return &JWTService{
// 		config:      cfg,
// 		companyRepo: companyRepo,
// 		logger:      logger,
// 	}
// }

// type CreateAccessTokenRequest struct {
// 	UserID           string
// 	Role             string
// 	DeviceID         string
// 	SessionType      string
// 	CompanyID        string
// 	IPAddress        string // ADD THIS IF MISSING
// 	AdminRoleLevel   string
// 	AdminPermissions []string
// }

// // // CreateAccessToken creates JWT with permission bitmask
// // func (s *JWTService) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (string, string, error) {
// // 	// Validate input parameters
// // 	if req.UserID == "" {
// // 		return "", "", fmt.Errorf("user ID is required")
// // 	}
// // 	if req.Role == "" {
// // 		return "", "", fmt.Errorf("role is required")
// // 	}
// // 	if req.DeviceID == "" {
// // 		return "", "", fmt.Errorf("device ID is required")
// // 	}
// // 	if req.SessionType == "" {
// // 		return "", "", fmt.Errorf("session type is required")
// // 	}

// // 	jti := uuid.NewString()
// // 	now := time.Now()

// // 	// Build Permission Mask
// // 	var permissionMask []uint64

// // 	if req.SessionType == "admin" {
// // 		// Admin → full access to all 229 permissions
// // 		permissionMask = s.buildFullAccessMask()
// // 		s.logger.Info("🔐 ADMIN session token - FULL permissions",
// // 			zap.String("admin_id", req.UserID),
// // 			zap.String("role", req.Role),
// // 			zap.Any("permission_mask", permissionMask))
// // 	} else {
// // 		// User session type - company RBAC
// // 		userID, err := uuid.Parse(req.UserID)
// // 		if err != nil {
// // 			return "", "", fmt.Errorf("invalid user ID format: %w", err)
// // 		}

// // 		if req.CompanyID == "" {
// // 			return "", "", fmt.Errorf("company ID is required for user sessions")
// // 		}

// // 		companyID, err := uuid.Parse(req.CompanyID)
// // 		if err != nil {
// // 			return "", "", fmt.Errorf("invalid company ID format: %w", err)
// // 		}

// // 		s.logger.Info("🔍 Fetching USER permission bitmask",
// // 			zap.String("user_id", req.UserID),
// // 			zap.String("company_id", req.CompanyID),
// // 			zap.String("session_type", req.SessionType),
// // 			zap.String("role", req.Role))

// // 		// Fetch permission mask from repository
// // 		mask, err := s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
// // 		if err != nil {
// // 			s.logger.Warn("⚠️ Failed to get user permission mask, using empty mask",
// // 				zap.String("user_id", req.UserID),
// // 				zap.String("company_id", req.CompanyID),
// // 				zap.Error(err))
// // 			permissionMask = []uint64{0, 0, 0, 0} // Empty mask for all 4 segments
// // 		} else {
// // 			permissionMask = mask
// // 			s.logger.Info("✅ User permission mask retrieved",
// // 				zap.String("user_id", req.UserID),
// // 				zap.String("company_id", req.CompanyID),
// // 				zap.Int("mask_segments", len(permissionMask)),
// // 				zap.Any("mask_values", permissionMask))

// // 			// Convert mask to permission names for debugging
// // 			permissions := rbac.GetPermissionsFromMask(permissionMask)
// // 			s.logger.Info("📋 Permissions in JWT token",
// // 				zap.String("user_id", req.UserID),
// // 				zap.Int("total_permissions", len(permissions)),
// // 				zap.Strings("permissions", permissions))

// // 			// Specifically check administrative permissions
// // 			adminPerms := []string{
// // 				"administrative.department.view",
// // 				"administrative.department.create",
// // 				"administrative.department.update",
// // 				"administrative.department.delete",
// // 				"administrative.employee.view",
// // 				"administrative.employee.manage",
// // 			}

// // 			var foundAdminPerms []string
// // 			for _, adminPerm := range adminPerms {
// // 				if rbac.HasPermission(permissionMask, adminPerm) {
// // 					foundAdminPerms = append(foundAdminPerms, adminPerm)
// // 				}
// // 			}

// // 			s.logger.Info("🏢 Administrative permissions check",
// // 				zap.String("user_id", req.UserID),
// // 				zap.Int("expected", len(adminPerms)),
// // 				zap.Int("found", len(foundAdminPerms)),
// // 				zap.Strings("found_permissions", foundAdminPerms))

// // 			if len(foundAdminPerms) < len(adminPerms) {
// // 				s.logger.Warn("❌ Missing administrative permissions in JWT!",
// // 					zap.String("user_id", req.UserID),
// // 					zap.Int("missing_count", len(adminPerms)-len(foundAdminPerms)))
// // 			}
// // 		}
// // 	} // <- ADDED THIS CLOSING BRACE FOR THE ELSE BLOCK

// // 	// Create Claims with Permission Mask
// // 	claims := &models.JWTClaims{
// // 		UserID:           req.UserID,
// // 		Role:             req.Role,
// // 		DeviceID:         req.DeviceID,
// // 		SessionType:      req.SessionType,
// // 		CompanyID:        req.CompanyID,
// // 		JTI:              jti,
// // 		IssuedAt:         now.Unix(),
// // 		ExpiresAt:        now.Add(s.config.JWT.AccessTTL).Unix(),
// // 		PermissionMask:   permissionMask,
// // 		AdminRoleLevel:   req.AdminRoleLevel,
// // 		AdminPermissions: req.AdminPermissions,
// // 	}

// // 	// Sign JWT
// // 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// // 	signed, err := token.SignedString([]byte(s.config.JWT.Secret))
// // 	if err != nil {
// // 		return "", "", fmt.Errorf("failed to sign token: %w", err)
// // 	}

// // 	s.logger.Info("🎫 JWT access token created successfully",
// // 		zap.String("user_id", req.UserID),
// // 		zap.String("session_type", req.SessionType),
// // 		zap.String("company_id", req.CompanyID),
// // 		zap.String("role", req.Role),
// // 		zap.String("jti", jti),
// // 		zap.Int64("expires_at", claims.ExpiresAt),
// // 		zap.Any("permission_mask", permissionMask))

// // 	return signed, jti, nil
// // }

// // Helper to build full access mask for admin
// func (s *JWTService) buildFullAccessMask() []uint64 {
// 	// We have 229 permissions, so we need 4 uint64s (229/64 = 3.57 -> 4)
// 	mask := make([]uint64, 4)
// 	for i := range mask {
// 		mask[i] = ^uint64(0) // Set all bits to 1
// 	}
// 	return mask
// }

// // ValidateAccessToken validates and parses JWT access token
// func (s *JWTService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
// 	if tokenStr == "" {
// 		return nil, fmt.Errorf("token string is empty")
// 	}

// 	token, err := jwt.ParseWithClaims(tokenStr, &models.JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
// 		// Verify signing method
// 		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
// 		}
// 		return []byte(s.config.JWT.Secret), nil
// 	})

// 	if err != nil {
// 		s.logger.Warn("JWT token parse failed", zap.Error(err))
// 		return nil, fmt.Errorf("token parse error: %w", err)
// 	}

// 	if !token.Valid {
// 		return nil, fmt.Errorf("invalid token")
// 	}

// 	claims, ok := token.Claims.(*models.JWTClaims)
// 	if !ok {
// 		return nil, fmt.Errorf("invalid token claims")
// 	}

// 	// Validate required claim fields
// 	if claims.UserID == "" {
// 		return nil, fmt.Errorf("token missing user ID")
// 	}
// 	if claims.SessionType == "" {
// 		return nil, fmt.Errorf("token missing session type")
// 	}

// 	// For non-admin sessions, validate CompanyID exists
// 	if claims.SessionType != "admin" && claims.CompanyID == "" {
// 		return nil, fmt.Errorf("non-admin token missing company ID")
// 	}

// 	s.logger.Debug("JWT token validated successfully",
// 		zap.String("user_id", claims.UserID),
// 		zap.String("session_type", claims.SessionType),
// 		zap.String("jti", claims.JTI))

// 	return claims, nil
// }

// // GenerateRefreshToken generates opaque refresh token
// func (s *JWTService) GenerateRefreshToken() (string, error) {
// 	b := make([]byte, 32)
// 	if _, err := rand.Read(b); err != nil {
// 		return "", fmt.Errorf("failed to generate random token: %w", err)
// 	}
// 	return hex.EncodeToString(b), nil
// }

// // CreateTokenPair creates both access and refresh tokens
// func (s *JWTService) CreateTokenPair(ctx context.Context, req *CreateAccessTokenRequest) (*models.TokenPairResponse, error) {
// 	accessToken, _, err := s.CreateAccessToken(ctx, req)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create access token: %w", err)
// 	}

// 	refreshToken, err := s.GenerateRefreshToken()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
// 	}

// 	return &models.TokenPairResponse{
// 		AccessToken:  accessToken,
// 		RefreshToken: refreshToken,
// 		ExpiresIn:    int(s.config.JWT.AccessTTL.Seconds()),
// 		TokenType:    "Bearer",
// 	}, nil
// }

// // VerifyTokenExpiration checks if token is expired (helper method)
// func (s *JWTService) VerifyTokenExpiration(claims *models.JWTClaims) bool {
// 	now := time.Now().Unix()
// 	return claims.ExpiresAt > now
// }



// // In jwt_service.go - CreateAccessToken method
// func (s *JWTService) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (string, string, error) {
//     // Validate input parameters
//     if req.UserID == "" {
//         return "", "", fmt.Errorf("user ID is required")
//     }
//     if req.Role == "" {
//         return "", "", fmt.Errorf("role is required")
//     }
//     if req.DeviceID == "" {
//         return "", "", fmt.Errorf("device ID is required")
//     }
//     if req.SessionType == "" {
//         return "", "", fmt.Errorf("session type is required")
//     }

//     jti := uuid.NewString()
//     now := time.Now()

//     // Build Permission Mask - use the specific company ID
//     var permissionMask []uint64

//     if req.SessionType == "admin" {
//         // Admin → full access to all 229 permissions
//         permissionMask = s.buildFullAccessMask()
//         s.logger.Info("🔐 ADMIN session token - FULL permissions",
//             zap.String("admin_id", req.UserID),
//             zap.String("role", req.Role),
//             zap.Any("permission_mask", permissionMask))
//     } else {
//         // User session type - company RBAC for SPECIFIC company
//         userID, err := uuid.Parse(req.UserID)
//         if err != nil {
//             return "", "", fmt.Errorf("invalid user ID format: %w", err)
//         }

//         if req.CompanyID == "" {
//             return "", "", fmt.Errorf("company ID is required for user sessions")
//         }

//         companyID, err := uuid.Parse(req.CompanyID)
//         if err != nil {
//             return "", "", fmt.Errorf("invalid company ID format: %w", err)
//         }

//         s.logger.Info("🔍 Fetching USER permission bitmask for specific company",
//             zap.String("user_id", req.UserID),
//             zap.String("company_id", req.CompanyID),
//             zap.String("session_type", req.SessionType),
//             zap.String("role", req.Role))

//         // Fetch permission mask from repository for THIS specific company
//         mask, err := s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
//         if err != nil {
//             s.logger.Warn("⚠️ Failed to get user permission mask, using empty mask",
//                 zap.String("user_id", req.UserID),
//                 zap.String("company_id", req.CompanyID),
//                 zap.Error(err))
//             permissionMask = []uint64{0, 0, 0, 0} // Empty mask for all 4 segments
//         } else {
//             permissionMask = mask
//             s.logger.Info("✅ User permission mask retrieved for company",
//                 zap.String("user_id", req.UserID),
//                 zap.String("company_id", req.CompanyID),
//                 zap.Int("mask_segments", len(permissionMask)),
//                 zap.Any("mask_values", permissionMask))

//             // Convert mask to permission names for debugging
//             permissions := rbac.GetPermissionsFromMask(permissionMask)
//             s.logger.Info("📋 Permissions in JWT token for company",
//                 zap.String("user_id", req.UserID),
//                 zap.String("company_id", req.CompanyID),
//                 zap.Int("total_permissions", len(permissions)),
//                 zap.Strings("permissions", permissions))
//         }
//     }

//     // Create Claims with Permission Mask and COMPANY ID
//     claims := &models.JWTClaims{
//         UserID:           req.UserID,
//         Role:             req.Role,
//         DeviceID:         req.DeviceID,
//         SessionType:      req.SessionType,
//         CompanyID:        req.CompanyID, // The specific company ID
//         JTI:              jti,
//         IssuedAt:         now.Unix(),
//         ExpiresAt:        now.Add(s.config.JWT.AccessTTL).Unix(),
//         PermissionMask:   permissionMask,
//         AdminRoleLevel:   req.AdminRoleLevel,
//         AdminPermissions: req.AdminPermissions,
//     }

//     // Sign JWT
//     token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//     signed, err := token.SignedString([]byte(s.config.JWT.Secret))
//     if err != nil {
//         return "", "", fmt.Errorf("failed to sign token: %w", err)
//     }

//     s.logger.Info("🎫 JWT access token created for specific company",
//         zap.String("user_id", req.UserID),
//         zap.String("session_type", req.SessionType),
//         zap.String("company_id", req.CompanyID),
//         zap.String("role", req.Role),
//         zap.String("jti", jti),
//         zap.Int64("expires_at", claims.ExpiresAt),
//         zap.Any("permission_mask", permissionMask))

//     return signed, jti, nil
// }