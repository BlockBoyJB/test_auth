package repo

import (
	"context"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo/pgdb"
	"test_auth/pkg/postgres"
)

type User interface {
	Create(ctx context.Context, u dbmodel.User) error
	FindById(ctx context.Context, userId string) (dbmodel.User, error)
	UpdateToken(ctx context.Context, userId, token string) error
}

type Repositories struct {
	User
}

func NewRepositories(pg *postgres.Postgres) *Repositories {
	return &Repositories{
		User: pgdb.NewUserRepo(pg),
	}
}
