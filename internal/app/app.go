package app

import (
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
	"test_auth/config"
	v1 "test_auth/internal/api/v1"
	"test_auth/internal/repo"
	"test_auth/internal/service"
	"test_auth/pkg/hasher"
	"test_auth/pkg/httpserver"
	"test_auth/pkg/postgres"
	"test_auth/pkg/smtp"
	"test_auth/pkg/validator"
)

func Run() {
	// config
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Config error: %s", err)
	}
	// set up json logger
	setLogger(cfg.Log.Level, cfg.Log.Output)

	// postgresql database
	pg, err := postgres.NewPG(cfg.PG.Url, postgres.MaxPoolSize(cfg.PG.MaxPoolSize))
	if err != nil {
		log.Fatalf("Initializing postgres error: %s", err)
	}
	defer pg.Close()

	d := &service.ServicesDependencies{
		Repos:      repo.NewRepositories(pg),
		Smtp:       smtp.NewSmtp(cfg.SMTP.Login, cfg.SMTP.Password),
		Hasher:     hasher.NewHasher(cfg.Hasher.Secret),
		SignKey:    cfg.JWT.SignKey,
		AccessTTL:  cfg.JWT.AccessTTL,
		RefreshTTL: cfg.JWT.RefreshTTL,
	}
	services := service.NewServices(d)

	// validator for incoming requests
	v, err := validator.NewValidator()
	if err != nil {
		log.Fatalf("Initializing handler validator error: %s", err)
	}

	// handler for incoming messages
	handler := echo.New()
	handler.Validator = v
	v1.LoggingMiddleware(handler, cfg.Log.Output)
	v1.NewRouter(handler, services)

	httpServer := httpserver.NewServer(handler, httpserver.Port(cfg.HTTP.Port))

	log.Infof("App started! Listening port %s", cfg.HTTP.Port)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-interrupt:
		log.Info("app run, signal " + s.String())

	case err = <-httpServer.Notify():
		log.Errorf("/app/run http server notify error: %s", err)
	}
	// graceful shutdown
	if err = httpServer.Shutdown(); err != nil {
		log.Errorf("/app/run http server shutdown error: %s", err)
	}

	log.Infof("App shutdown with exit code 0")
}

// loading environment params from .env
func init() {
	if _, ok := os.LookupEnv("HTTP_PORT"); !ok {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("load env file error: %s", err)
		}
	}
}
