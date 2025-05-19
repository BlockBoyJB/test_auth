package pgdb

import (
	"context"
	"errors"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/suite"
	"test_auth/pkg/postgres"
	"testing"
)

type pgdbTestSuite struct {
	suite.Suite
	ctx  context.Context
	pg   *postgres.Postgres
	m    *migrate.Migrate
	auth *AuthRepo
}

func (s *pgdbTestSuite) SetupTest() {
	testPGUrl := "postgres://postgres:1234567890@localhost:6000/postgres"
	m, err := migrate.New("file://../../../migrations", testPGUrl+"?sslmode=disable")
	if err != nil {
		panic(err)
	}
	if err = m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		panic(err)
	}
	s.m = m

	s.ctx = context.Background()

	pg, err := postgres.NewPG(testPGUrl)
	if err != nil {
		panic(err)
	}
	s.pg = pg

	s.auth = NewAuthRepo(pg)
}

func (s *pgdbTestSuite) TearDownTest() {
	_ = s.m.Drop()
	s.pg.Close()
}

func TestPGDB(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	suite.Run(t, new(pgdbTestSuite))
}
