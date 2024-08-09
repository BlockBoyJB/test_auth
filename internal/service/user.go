package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo"
	"test_auth/internal/repo/pgerrs"
	"test_auth/pkg/hasher"
)

const userServicePrefixLog = "/service/user"

type userService struct {
	user   repo.User
	hasher hasher.Hasher
}

func newUserService(user repo.User, hasher hasher.Hasher) *userService {
	return &userService{
		user:   user,
		hasher: hasher,
	}
}

func (s *userService) Create(ctx context.Context, input UserCreateInput) (string, error) {
	userId := uuid.NewString()
	err := s.user.Create(ctx, dbmodel.User{
		UserId:   userId,
		Email:    input.Email,
		Password: s.hasher.Hash(input.Password),
	})
	if err != nil {
		if errors.Is(err, pgerrs.ErrAlreadyExist) {
			return "", ErrUserAlreadyExists
		}
		log.Errorf("%s/Create error create user: %s", userServicePrefixLog, err)
		return "", err
	}
	return userId, nil
}

func (s *userService) Verify(ctx context.Context, userId, password string) (bool, error) {
	u, err := s.user.FindById(ctx, userId)
	if err != nil {
		if errors.Is(err, pgerrs.ErrNotFound) {
			return false, ErrUserNotFound
		}
		log.Errorf("%s/Verify error find user by id: %s", userServicePrefixLog, err)
		return false, err
	}
	return s.hasher.Verify(password, u.Password), nil
}
