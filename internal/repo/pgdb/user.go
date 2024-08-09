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

type UserRepo struct {
	*postgres.Postgres
}

func NewUserRepo(pg *postgres.Postgres) *UserRepo {
	return &UserRepo{pg}
}

func (r *UserRepo) Create(ctx context.Context, u dbmodel.User) error {
	sql, args, _ := r.Builder.
		Insert("users").
		Columns("user_id", "email", "password").
		Values(u.UserId, u.Email, u.Password).
		ToSql()
	if _, err := r.Pool.Exec(ctx, sql, args...); err != nil {
		var pgErr *pgconn.PgError
		if ok := errors.As(err, &pgErr); ok {
			if pgErr.Code == "23505" {
				return pgerrs.ErrAlreadyExist
			}
		}
		return err
	}
	return nil
}

func (r *UserRepo) FindById(ctx context.Context, userId string) (dbmodel.User, error) {
	sql, args, _ := r.Builder.
		Select("id, email, password, refresh_token").
		From("users").
		Where("user_id = ?", userId).
		ToSql()

	var u dbmodel.User
	err := r.Pool.QueryRow(ctx, sql, args...).Scan(
		&u.Id,
		&u.Email,
		&u.Password,
		&u.RefreshToken,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbmodel.User{}, pgerrs.ErrNotFound
		}
		return dbmodel.User{}, err
	}
	return u, nil
}

func (r *UserRepo) UpdateToken(ctx context.Context, userId, token string) error {
	sql, args, _ := r.Builder.
		Update("users").
		Set("refresh_token", token).
		Where("user_id = ?", userId).
		ToSql()

	if _, err := r.Pool.Exec(ctx, sql, args...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pgerrs.ErrNotFound
		}
		return err
	}
	return nil
}
