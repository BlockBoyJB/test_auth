package config

import (
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"time"
)

type Config struct {
	HTTP HTTP
	Log  Log
	PG   PG
	Auth Auth
}

type (
	HTTP struct {
		Port string `env-required:"true" env:"HTTP_PORT"`
	}
	Log struct {
		Level  string `env-required:"true" env:"LOG_LEVEL"`
		Output string `env-required:"true" env:"LOG_OUTPUT"`
	}
	PG struct {
		Url string `env-required:"true" env:"PG_URL"`
	}
	Auth struct {
		SignKey    string        `env-required:"true" env:"SIGN_KEY"`
		Webhook    string        `env-required:"true" env:"AUTH_WEBHOOK"`
		AccessTTL  time.Duration `env-required:"true" env:"ACCESS_TTL"`
		RefreshTTL time.Duration `env-required:"true" env:"REFRESH_TTL"`
	}
)

func NewConfig() (*Config, error) {
	c := &Config{}
	if err := cleanenv.ReadEnv(c); err != nil {
		return nil, fmt.Errorf("error reading config env: %w", err)
	}
	return c, nil
}
