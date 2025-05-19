package service

import "errors"

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidUserAgent = errors.New("invalid user-agent")
)
