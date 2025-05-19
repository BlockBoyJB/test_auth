package repo

import (
	"context"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo/pgdb"
	"test_auth/pkg/postgres"
)

type Auth interface {
	Create(ctx context.Context, a dbmodel.Auth) error
	Find(ctx context.Context, jti string) (dbmodel.Auth, error)
	Revoke(ctx context.Context, jti string) error
}

type Repositories struct {
	Auth
}

func NewRepositories(pg *postgres.Postgres) *Repositories {
	return &Repositories{
		Auth: pgdb.NewAuthRepo(pg),
	}
}
