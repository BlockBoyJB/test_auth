package config

import (
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"time"
)

type Config struct {
	HTTP   HTTP
	Log    Log
	PG     PG
	Hasher Hasher
	JWT    JWT
	SMTP   SMTP
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
		MaxPoolSize int    `env-required:"true" env:"PG_MAX_POOL_SIZE"`
		Url         string `env-required:"true" env:"PG_URL"`
	}
	Hasher struct {
		Secret string `env-required:"true" env:"HASHER_SECRET"`
	}
	JWT struct {
		SignKey    string        `env-required:"true" env:"JWT_SIGN_KEY"`
		AccessTTL  time.Duration `env-required:"true" env:"JWT_ACCESS_TTL"`
		RefreshTTL time.Duration `env-required:"true" env:"JWT_REFRESH_TTL"`
	}
	SMTP struct {
		Login    string `env-required:"true" env:"SMTP_LOGIN"`
		Password string `env-required:"true" env:"SMTP_PASS"`
	}
)

func NewConfig() (*Config, error) {
	c := &Config{}
	if err := cleanenv.ReadEnv(c); err != nil {
		return nil, fmt.Errorf("error reading config env: %w", err)
	}
	return c, nil
}
