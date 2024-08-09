package service

import (
	"context"
	"test_auth/internal/repo"
	"test_auth/pkg/hasher"
	"test_auth/pkg/smtp"
	"time"
)

type (
	UserCreateInput struct {
		Email    string
		Password string
	}
)

type Auth interface {
	CreateTokens(ctx context.Context, remoteAddr, userId string) (string, string, error)
	RefreshToken(ctx context.Context, remoteAddr, refreshToken string) (string, string, error)
}

type User interface {
	Create(ctx context.Context, input UserCreateInput) (string, error)
	Verify(ctx context.Context, userId, password string) (bool, error)
}

type (
	Services struct {
		Auth Auth
		User User
	}
	ServicesDependencies struct {
		Repos      *repo.Repositories
		Smtp       smtp.Smtp
		Hasher     hasher.Hasher
		SignKey    string
		AccessTTL  time.Duration
		RefreshTTL time.Duration
	}
)

func NewServices(d *ServicesDependencies) *Services {
	return &Services{
		Auth: newAuthService(d.Repos.User, d.Smtp, d.SignKey, d.AccessTTL, d.RefreshTTL),
		User: newUserService(d.Repos.User, d.Hasher),
	}
}
