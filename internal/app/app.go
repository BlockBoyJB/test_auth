package app

import (
	"context"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"test_auth/config"
	v1 "test_auth/internal/controller/http/v1"
	"test_auth/internal/repo"
	"test_auth/internal/service"
	"test_auth/internal/token"
	"test_auth/internal/webhook"
	"test_auth/pkg/postgres"
	"test_auth/pkg/validator"
	"time"
)

//	@title			Auth Service
//	@version		1.0
//	@description	Auth service. Includes access (jwt), refresh (base64) tokens

//	@host		localhost:8000
//	@BasePath	/

//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				input token in format "Bearer {token}"

func Run() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("init config error")
	}

	setLogger(cfg.Log.Level, cfg.Log.Output)

	// POSTGRESQL
	pg, err := postgres.NewPG(cfg.PG.Url)
	if err != nil {
		log.Fatal().Err(err).Msg("init postgres error")
	}
	defer pg.Close()

	// INIT SERVICES
	d := &service.ServicesDependencies{
		Repos:      repo.NewRepositories(pg),
		Token:      token.NewTokenService(cfg.Auth.SignKey),
		Webhook:    webhook.NewWebhook(cfg.Auth.Webhook),
		AccessTTL:  cfg.Auth.AccessTTL,
		RefreshTTL: cfg.Auth.RefreshTTL,
	}

	services := service.NewServices(d)

	// HTTP handler
	h := echo.New()

	h.Validator = validator.NewValidator()

	v1.NewRouter(h, services)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	handlerCh := make(chan error, 1)

	go func() {
		handlerCh <- h.Start(net.JoinHostPort("", cfg.HTTP.Port))
	}()

	log.Info().Msgf("app started, listen port %s", cfg.HTTP.Port)

	select {
	case s := <-interrupt:
		log.Info().Msgf("app signal %s", s.String())
	case err = <-handlerCh:
		log.Err(err).Msg("http server error")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// stop http server
	if err = h.Shutdown(ctx); err != nil {
		log.Err(err).Msg("http server shutdown error")
	}

	log.Info().Msg("app shutdown with exit code 0")
}

func init() {
	if _, ok := os.LookupEnv("HTTP_PORT"); !ok {
		if err := godotenv.Load(); err != nil {
			log.Fatal().Err(err).Msg("load env file error")
		}
	}
}
