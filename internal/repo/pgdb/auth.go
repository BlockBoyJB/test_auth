package pgdb

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo/pgerrs"
	"test_auth/pkg/postgres"
)

const (
	authTable = "auth"
)

type AuthRepo struct {
	*postgres.Postgres
}

func NewAuthRepo(pg *postgres.Postgres) *AuthRepo {
	return &AuthRepo{pg}
}

func (r *AuthRepo) Create(ctx context.Context, a dbmodel.Auth) error {
	sql, args, _ := r.Builder.
		Insert(authTable).
		Columns("user_id", "user_agent", "ip", "token", "jti", "expires_at").
		Values(a.UserId, a.UserAgent, a.IP, a.Token, a.JTI, a.ExpiresAt).
		ToSql()

	if _, err := r.Pool.Exec(ctx, sql, args...); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return pgerrs.ErrAlreadyExists
			}
		}
		return err
	}
	return nil
}

func (r *AuthRepo) Find(ctx context.Context, jti string) (dbmodel.Auth, error) {
	sql, args, _ := r.Builder.
		Select("user_id", "user_agent", "ip", "token", "revoked", "expires_at").
		From(authTable).Where("jti = ?", jti).
		ToSql()

	var a dbmodel.Auth
	err := r.Pool.QueryRow(ctx, sql, args...).Scan(
		&a.UserId,
		&a.UserAgent,
		&a.IP,
		&a.Token,
		&a.Revoked,
		&a.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbmodel.Auth{}, pgerrs.ErrNotFound
		}
	}
	return a, nil
}

func (r *AuthRepo) Revoke(ctx context.Context, jti string) error {
	sql, args, _ := r.Builder.
		Update(authTable).
		Set("revoked", true).
		Where("jti = ?", jti).
		ToSql()

	if _, err := r.Pool.Exec(ctx, sql, args...); err != nil {
		return err
	}
	return nil
}
