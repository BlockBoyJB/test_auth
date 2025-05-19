package pgdb

import (
	"github.com/google/uuid"
	"test_auth/internal/model/dbmodel"
	"test_auth/internal/repo/pgerrs"
	"testing"
	"time"
)

func (s *pgdbTestSuite) TestAuthRepo_Create() {
	testCases := []struct {
		testName  string
		auth      dbmodel.Auth
		expectErr error
	}{
		{
			testName: "correct test",
			auth: dbmodel.Auth{
				UserId:    "foobar",
				UserAgent: "GOOGLE",
				IP:        "127.0.0.1",
				Token:     "base64token",
				JTI:       "myuuid4",
				ExpiresAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			expectErr: nil,
		},
		{
			testName: "jti already exists",
			auth: dbmodel.Auth{
				UserId:    "barfoo",
				UserAgent: "EDGE",
				IP:        "192.168.0.0",
				Token:     "anotherbase64token",
				JTI:       "myuuid4",
				ExpiresAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
			},
			expectErr: pgerrs.ErrAlreadyExists,
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.testName, func(t *testing.T) {
			err := s.auth.Create(s.ctx, tc.auth)
			s.Assert().Equal(tc.expectErr, err)

			if tc.expectErr == nil {
				sql, args, _ := s.pg.Builder.
					Select("user_id", "user_agent", "ip", "token", "jti", "revoked", "expires_at").
					From(authTable).
					Where("jti = ?", tc.auth.JTI).
					ToSql()

				var actual dbmodel.Auth
				err = s.pg.Pool.QueryRow(s.ctx, sql, args...).Scan(
					&actual.UserId,
					&actual.UserAgent,
					&actual.IP,
					&actual.Token,
					&actual.JTI, // чтобы было проще проверять)
					&actual.Revoked,
					&actual.ExpiresAt,
				)
				s.Assert().Nil(err)
				s.Assert().Equal(tc.auth, actual)
			}
		})
	}
}

func (s *pgdbTestSuite) setupTestData() dbmodel.Auth {
	a := dbmodel.Auth{
		UserId:    "vasya",
		UserAgent: "GOOGLE",
		IP:        "127.0.0.1",
		Token:     "foobartoken",
		JTI:       uuid.NewString(),
		ExpiresAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	sql, args, _ := s.pg.Builder.
		Insert(authTable).
		Columns("user_id", "user_agent", "ip", "token", "jti", "expires_at").
		Values(a.UserId, a.UserAgent, a.IP, a.Token, a.JTI, a.ExpiresAt).
		ToSql()

	if _, err := s.pg.Pool.Exec(s.ctx, sql, args...); err != nil {
		panic(err)
	}
	return a
}

func (s *pgdbTestSuite) TestAuthRepo_Find() {
	expectJTI := uuid.NewString()
	expectAuth := dbmodel.Auth{
		UserId:    "vasya",
		UserAgent: "GOOGLE",
		IP:        "127.0.0.1",
		Token:     "foobartoken",
		ExpiresAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	sql, args, _ := s.pg.Builder.
		Insert(authTable).
		Columns("user_id", "user_agent", "ip", "token", "jti", "expires_at").
		Values(expectAuth.UserId, expectAuth.UserAgent, expectAuth.IP, expectAuth.Token, expectJTI, expectAuth.ExpiresAt).
		ToSql()

	if _, err := s.pg.Pool.Exec(s.ctx, sql, args...); err != nil {
		panic(err)
	}

	testCases := []struct {
		testName     string
		jti          string
		expectOutput dbmodel.Auth
		expectErr    error
	}{
		{
			testName:     "correct test",
			jti:          expectJTI,
			expectOutput: expectAuth,
			expectErr:    nil,
		},
		{
			testName:     "not found",
			jti:          "foobar",
			expectOutput: dbmodel.Auth{},
			expectErr:    pgerrs.ErrNotFound,
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.testName, func(t *testing.T) {
			a, err := s.auth.Find(s.ctx, tc.jti)

			s.Assert().Equal(tc.expectErr, err)
			s.Assert().Equal(tc.expectOutput, a)
		})
	}
}

func (s *pgdbTestSuite) TestAuthRepo_Revoke() {
	a := dbmodel.Auth{
		UserId:    "vasya",
		UserAgent: "GOOGLE",
		IP:        "127.0.0.1",
		Token:     "foobartoken",
		JTI:       uuid.NewString(),
		ExpiresAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	sql, args, _ := s.pg.Builder.
		Insert(authTable).
		Columns("user_id", "user_agent", "ip", "token", "jti", "expires_at").
		Values(a.UserId, a.UserAgent, a.IP, a.Token, a.JTI, a.ExpiresAt).
		ToSql()

	if _, err := s.pg.Pool.Exec(s.ctx, sql, args...); err != nil {
		panic(err)
	}

	testCases := []struct {
		testName     string
		JTI          string
		expectStatus bool
		expectErr    error
	}{
		{
			testName:     "correct test",
			JTI:          a.JTI,
			expectStatus: true,
			expectErr:    nil,
		},
		{
			testName:     "not found",
			JTI:          "foobar",
			expectStatus: false,
			expectErr:    nil,
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.testName, func(t *testing.T) {
			err := s.auth.Revoke(s.ctx, tc.JTI)
			s.Assert().Equal(tc.expectErr, err)

			sql, args, _ = s.pg.Builder.
				Select("revoked").
				From(authTable).
				Where("jti = ?", tc.JTI).
				ToSql()

			var actual bool
			err = s.pg.Pool.QueryRow(s.ctx, sql, args...).Scan(&actual)
			s.Assert().Equal(tc.expectStatus, actual)
		})
	}
}
