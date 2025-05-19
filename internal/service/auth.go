package service

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo"
	"test_auth/internal/repo/pgerrs"
	"test_auth/internal/token"
	"test_auth/internal/webhook"
	"time"
)

type authService struct {
	auth       repo.Auth
	token      token.Token
	webhook    webhook.Webhook
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func newAuthService(auth repo.Auth, token token.Token, webhook webhook.Webhook, accessTTL, refreshTTL time.Duration) *authService {
	return &authService{
		auth:       auth,
		token:      token,
		webhook:    webhook,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (s *authService) SignIn(ctx context.Context, input TokenInput) (TokenOutput, error) {
	return s.tokenPair(ctx, input)
}

func (s *authService) Refresh(ctx context.Context, input RefreshInput) (TokenOutput, error) {
	c, err := s.parseClaims(input.Access)
	if err != nil {
		return TokenOutput{}, err
	}

	a, err := s.auth.Find(ctx, c.ID)
	if err != nil {
		if errors.Is(err, pgerrs.ErrNotFound) {
			return TokenOutput{}, ErrInvalidToken
		}
		log.Err(err).Str("user_id", c.UserId).Msg("auth/Refresh error find auth data in database")
		return TokenOutput{}, err
	}

	if a.UserAgent != input.UserAgent {
		if err = s.auth.Revoke(ctx, c.ID); err != nil {
			log.Err(err).Str("user_id", c.UserId).Msg("auth/Refresh error revoke current session in database")
			return TokenOutput{}, err
		}
		return TokenOutput{}, ErrInvalidUserAgent
	}

	if a.Revoked || a.ExpiresAt.Before(time.Now()) || a.UserId != c.UserId {
		return TokenOutput{}, ErrInvalidToken
	}

	if ok := s.token.ValidateRefresh(a.Token, input.Refresh); !ok {
		return TokenOutput{}, ErrInvalidToken
	}

	if a.IP != input.IP {
		err = s.webhook.Request(webhook.Body{
			UserId:    a.UserId,
			NewIP:     input.IP,
			OldIP:     a.IP,
			UserAgent: a.UserAgent,
			Timestamp: time.Now().Round(time.Second),
		})
		if err != nil {
			log.Err(err).Str("user_id", a.UserId).Msg("auth/Refresh ip does not match: error make webhook request")
			return TokenOutput{}, err
		}
	}

	if err = s.auth.Revoke(ctx, c.ID); err != nil {
		log.Err(err).Str("user_id", c.UserId).Msg("auth/Refresh error revoke refresh token in database")
		return TokenOutput{}, err
	}
	return s.tokenPair(ctx, TokenInput{
		UserId:    c.UserId,
		UserAgent: input.UserAgent,
		IP:        input.IP,
	})
}

func (s *authService) Logout(ctx context.Context, access string) error {
	c, err := s.parseClaims(access)
	if err != nil {
		return err
	}

	if c.ExpiresAt.Before(time.Now()) {
		return ErrInvalidToken
	}
	if err = s.auth.Revoke(ctx, c.ID); err != nil {
		log.Err(err).Str("user_id", c.UserId).Msg("auth/Logout error revoke tokens in database")
		return err
	}
	return nil
}

func (s *authService) GetID(ctx context.Context, access string) (string, error) {
	c, err := s.parseClaims(access)
	if err != nil {
		return "", err
	}

	if c.ExpiresAt.Before(time.Now()) {
		return "", ErrInvalidToken
	}
	a, err := s.auth.Find(ctx, c.ID)
	if err != nil {
		if errors.Is(err, pgerrs.ErrNotFound) {
			return "", ErrInvalidToken
		}
		log.Err(err).Str("user_id", c.UserId).Msg("auth/GetID error find auth data in database")
		return "", err
	}
	if a.Revoked { // проверяем, что токен не используется после logout операции
		return "", ErrInvalidToken
	}
	return c.UserId, nil
}

type authClaims struct {
	jwt.RegisteredClaims
	UserId string `json:"user_id"`
}

func (s *authService) tokenPair(ctx context.Context, input TokenInput) (TokenOutput, error) {
	now := time.Now().Round(time.Second)
	jti := s.token.CreateJTI()

	access, err := s.token.Create(&authClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserId: input.UserId,
	})
	if err != nil {
		log.Err(err).Str("user_id", input.UserId).Msg("auth/tokenPair error create access token")
		return TokenOutput{}, err
	}

	refresh, hashedRefresh, err := s.token.CreateRefresh()
	if err != nil {
		log.Err(err).Str("user_id", input.UserId).Msg("auth/tokenPair error create refresh token")
		return TokenOutput{}, err
	}

	err = s.auth.Create(ctx, dbmodel.Auth{
		UserId:    input.UserId,
		UserAgent: input.UserAgent,
		IP:        input.IP,
		Token:     hashedRefresh,
		JTI:       jti,
		ExpiresAt: now.Add(s.refreshTTL).Round(time.Second),
	})
	if err != nil {
		log.Err(err).Str("user_id", input.UserId).Msg("auth/tokenPair error save refresh token in database")
		return TokenOutput{}, err
	}

	return TokenOutput{
		Access:  access,
		Refresh: refresh,
	}, nil
}

func (s *authService) parseClaims(token string) (*authClaims, error) {
	claims, err := s.token.Parse(token, &authClaims{})
	if err != nil {
		return nil, ErrInvalidToken
	}
	c, ok := claims.(*authClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return c, nil
}
