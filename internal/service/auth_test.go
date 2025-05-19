package service

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"test_auth/internal/mocks/repomocks"
	"test_auth/internal/mocks/tokenmocks"
	"test_auth/internal/mocks/webhookmocks"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo/pgerrs"
	"test_auth/internal/webhook"
	"testing"
	"time"
)

func correctTokenPair(ctx context.Context, input *TokenInput, auth *repomocks.MockAuth, token *tokenmocks.MockToken) {
	now := time.Now().Round(time.Second)
	token.EXPECT().CreateJTI().Return("UUID-STRING")
	token.EXPECT().Create(&authClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "UUID-STRING",
		},
		UserId: input.UserId,
	}).Return("ACCESS", nil)
	token.EXPECT().CreateRefresh().Return("REFRESH", "HASHED", nil)
	auth.EXPECT().Create(ctx, dbmodel.Auth{
		UserId:    input.UserId,
		UserAgent: input.UserAgent,
		IP:        input.IP,
		Token:     "HASHED",
		JTI:       "UUID-STRING",
		ExpiresAt: now,
	}).Return(nil)
}

func TestAuthService_SignIn(t *testing.T) {
	type args struct {
		ctx   context.Context
		input TokenInput
	}

	type mockBehaviour func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		expectOutput  TokenOutput
		expectErr     error
	}{
		{
			testName: "correct test",
			args: args{
				ctx: context.Background(),
				input: TokenInput{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				correctTokenPair(a.ctx, &a.input, auth, token)
			},
			expectOutput: TokenOutput{
				Access:  "ACCESS",
				Refresh: "REFRESH",
			},
			expectErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			repo := repomocks.NewMockAuth(ctrl)
			token := tokenmocks.NewMockToken(ctrl)
			tc.mockBehaviour(repo, token, tc.args)

			s := newAuthService(repo, token, nil, 0, 0)

			to, err := s.SignIn(tc.args.ctx, tc.args.input)

			assert.Equal(t, tc.expectOutput, to)
			assert.Equal(t, tc.expectErr, err)
		})
	}
}

func TestAuthService_Refresh(t *testing.T) {
	type args struct {
		ctx   context.Context
		input RefreshInput
	}

	type mockBehaviour func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		expectOutput  TokenOutput
		expectErr     error
	}{
		{
			testName: "correct test",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					Refresh:   "REFRESH",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse(a.input.Access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
					Token:     "HASHED",
					JTI:       "UUID-STRING",
					Revoked:   false,
					ExpiresAt: time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC),
				}, nil)
				token.EXPECT().ValidateRefresh("HASHED", "REFRESH").Return(true)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(nil)

				ti := &TokenInput{
					UserId:    "USER",
					UserAgent: a.input.UserAgent,
					IP:        a.input.IP,
				}
				correctTokenPair(a.ctx, ti, auth, token)
			},
			expectOutput: TokenOutput{
				Access:  "ACCESS",
				Refresh: "REFRESH",
			},
			expectErr: nil,
		},
		{
			testName: "ip does not match",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					Refresh:   "REFRESH",
					UserAgent: "GOOGLE",
					IP:        "192.168.0.0",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, wh *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse(a.input.Access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
					Token:     "HASHED",
					JTI:       "UUID-STRING",
					Revoked:   false,
					ExpiresAt: time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC),
				}, nil)
				token.EXPECT().ValidateRefresh("HASHED", "REFRESH").Return(true)
				wh.EXPECT().Request(webhook.Body{
					UserId:    "USER",
					NewIP:     "192.168.0.0",
					OldIP:     "127.0.0.1",
					UserAgent: "GOOGLE",
					Timestamp: time.Now().Round(time.Second),
				}).Return(nil)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(nil)

				ti := &TokenInput{
					UserId:    "USER",
					UserAgent: a.input.UserAgent,
					IP:        a.input.IP,
				}
				correctTokenPair(a.ctx, ti, auth, token)
			},
			expectOutput: TokenOutput{
				Access:  "ACCESS",
				Refresh: "REFRESH",
			},
			expectErr: nil,
		},
		{
			testName: "webhook request error",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					Refresh:   "REFRESH",
					UserAgent: "GOOGLE",
					IP:        "192.168.0.0",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, wh *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse(a.input.Access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
					Token:     "HASHED",
					JTI:       "UUID-STRING",
					Revoked:   false,
					ExpiresAt: time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC),
				}, nil)
				token.EXPECT().ValidateRefresh("HASHED", "REFRESH").Return(true)
				wh.EXPECT().Request(webhook.Body{
					UserId:    "USER",
					NewIP:     "192.168.0.0",
					OldIP:     "127.0.0.1",
					UserAgent: "GOOGLE",
					Timestamp: time.Now().Round(time.Second),
				}).Return(errors.New("some error"))
			},
			expectErr: errors.New("some error"),
		},
		{
			testName: "invalid token",
			args: args{
				input: RefreshInput{
					Access: "INVALID_ACCESS",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("INVALID_ACCESS", &authClaims{}).Return(&authClaims{}, errors.New("invalid sign method"))
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "pair of tokens not found",
			args: args{
				input: RefreshInput{
					Access: "ACCESS",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{}, pgerrs.ErrNotFound)

			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "pair of tokens not found unexpected error",
			args: args{
				input: RefreshInput{
					Access: "ACCESS",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{}, errors.New("some error"))

			},
			expectErr: errors.New("some error"),
		},
		{
			testName: "user agent does not match",
			args: args{
				input: RefreshInput{
					Access:    "ACCESS",
					UserAgent: "EDGE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserAgent: "GOOGLE",
				}, nil)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(nil)

			},
			expectErr: ErrInvalidUserAgent,
		},
		{
			testName: "error during revoke token #1",
			args: args{
				input: RefreshInput{
					Access:    "ACCESS",
					UserAgent: "EDGE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserAgent: "GOOGLE",
				}, nil)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(errors.New("some error"))

			},
			expectErr: errors.New("some error"),
		},
		{
			testName: "revoked token",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					UserAgent: "GOOGLE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					Revoked:   true,
					ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "expired refresh token",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					UserAgent: "GOOGLE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					Revoked:   false,
					ExpiresAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "user id does not match",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					UserAgent: "GOOGLE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "OTHER_USER",
					UserAgent: "GOOGLE",
					Revoked:   false,
					ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "invalid refresh",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					Refresh:   "INVALID_REFRESH",
					UserAgent: "GOOGLE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					Token:     "HASHED",
					Revoked:   false,
					ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil)
				token.EXPECT().ValidateRefresh("HASHED", "INVALID_REFRESH").Return(false)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "revoke error",
			args: args{
				ctx: context.Background(),
				input: RefreshInput{
					Access:    "ACCESS",
					Refresh:   "REFRESH",
					UserAgent: "GOOGLE",
				},
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, webhook *webhookmocks.MockWebhook, a args) {
				token.EXPECT().Parse("ACCESS", &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:    "USER",
					UserAgent: "GOOGLE",
					Token:     "HASHED",
					Revoked:   false,
					ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil)
				token.EXPECT().ValidateRefresh("HASHED", "REFRESH").Return(true)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(errors.New("some error"))
			},
			expectErr: errors.New("some error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			repo := repomocks.NewMockAuth(ctrl)
			token := tokenmocks.NewMockToken(ctrl)
			wh := webhookmocks.NewMockWebhook(ctrl)

			tc.mockBehaviour(repo, token, wh, tc.args)

			s := newAuthService(repo, token, wh, 0, 0)

			to, err := s.Refresh(tc.args.ctx, tc.args.input)

			assert.Equal(t, tc.expectOutput, to)
			assert.Equal(t, tc.expectErr, err)
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	type args struct {
		ctx    context.Context
		access string
	}

	type mockBehaviour func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		expectErr     error
	}{
		{
			testName: "correct test",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(nil)
			},
			expectErr: nil,
		},
		{
			testName: "parse access error",
			args: args{
				ctx:    context.Background(),
				access: "INVALID_ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, errors.New("parse error"))
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "expired access",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2001, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2000, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "expired access",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Revoke(a.ctx, "UUID-STRING").Return(errors.New("some error"))
			},
			expectErr: errors.New("some error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			repo := repomocks.NewMockAuth(ctrl)
			token := tokenmocks.NewMockToken(ctrl)
			tc.mockBehaviour(repo, token, tc.args)

			s := newAuthService(repo, token, nil, 0, 0)

			err := s.Logout(tc.args.ctx, tc.args.access)

			assert.Equal(t, tc.expectErr, err)
		})
	}
}

func TestAuthService_GetID(t *testing.T) {
	type args struct {
		ctx    context.Context
		access string
	}

	type mockBehaviour func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		expectID      string
		expectErr     error
	}{
		{
			testName: "correct test",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:  "USER",
					Revoked: false,
				}, nil)
			},
			expectID:  "USER",
			expectErr: nil,
		},
		{
			testName: "expired token",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2001, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2000, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "not found",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{}, pgerrs.ErrNotFound)
			},
			expectErr: ErrInvalidToken,
		},
		{
			testName: "find unexpected error",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{}, errors.New("some error"))
			},
			expectErr: errors.New("some error"),
		},
		{
			testName: "revoked token",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(auth *repomocks.MockAuth, token *tokenmocks.MockToken, a args) {
				token.EXPECT().Parse(a.access, &authClaims{}).Return(&authClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)),
						IssuedAt:  jwt.NewNumericDate(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)),
						ID:        "UUID-STRING",
					},
					UserId: "USER",
				}, nil)
				auth.EXPECT().Find(a.ctx, "UUID-STRING").Return(dbmodel.Auth{
					UserId:  "USER",
					Revoked: true,
				}, nil)
			},
			expectErr: ErrInvalidToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			repo := repomocks.NewMockAuth(ctrl)
			token := tokenmocks.NewMockToken(ctrl)
			tc.mockBehaviour(repo, token, tc.args)

			s := newAuthService(repo, token, nil, 0, 0)

			id, err := s.GetID(tc.args.ctx, tc.args.access)

			assert.Equal(t, tc.expectID, id)
			assert.Equal(t, tc.expectErr, err)
		})
	}
}
