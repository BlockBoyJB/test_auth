package service

import (
	"context"
	"test_auth/internal/repo"
	"test_auth/internal/token"
	"test_auth/internal/webhook"
	"time"
)

type (
	TokenInput struct {
		UserId    string
		UserAgent string
		IP        string
	}

	RefreshInput struct {
		Access    string
		Refresh   string
		UserAgent string
		IP        string
	}

	TokenOutput struct {
		Access  string `json:"access"`
		Refresh string `json:"refresh"`
	}
)

type Auth interface {
	SignIn(ctx context.Context, input TokenInput) (TokenOutput, error)
	Refresh(ctx context.Context, input RefreshInput) (TokenOutput, error)
	Logout(ctx context.Context, access string) error
	GetID(ctx context.Context, access string) (string, error)
}

type Services struct {
	Auth Auth
}

type ServicesDependencies struct {
	Repos      *repo.Repositories
	Token      token.Token
	Webhook    webhook.Webhook
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func NewServices(d *ServicesDependencies) *Services {
	return &Services{
		Auth: newAuthService(d.Repos.Auth, d.Token, d.Webhook, d.AccessTTL, d.RefreshTTL),
	}
}
