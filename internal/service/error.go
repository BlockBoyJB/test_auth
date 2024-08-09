package service

import "errors"

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")

	ErrIncorrectSignMethod = errors.New("incorrect sign method")
	ErrInvalidToken        = errors.New("invalid token")
	ErrCannotParseToken    = errors.New("cannot parse token")
	ErrCannotRefreshToken  = errors.New("cannot refresh token")
)
