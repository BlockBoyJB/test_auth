package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Token interface {
	Parse(token string, claims jwt.Claims) (jwt.Claims, error)
	Create(claims jwt.Claims) (string, error)
	CreateRefresh() (string, string, error)
	ValidateRefresh(hashed, refresh string) bool
	CreateJTI() string
}

type tokenService struct {
	signKey []byte
}

func NewTokenService(key string) Token {
	return &tokenService{
		signKey: []byte(key),
	}
}

func (s *tokenService) Parse(tokenString string, claims jwt.Claims) (jwt.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid sign method")
		}
		return s.signKey, nil
	})
	if err != nil {
		return nil, err
	}
	return token.Claims, nil
}

func (s *tokenService) Create(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(s.signKey)
}

func (s *tokenService) CreateRefresh() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	refresh := base64.RawURLEncoding.EncodeToString(buf)

	hashed, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return refresh, string(hashed), nil
}

func (s *tokenService) ValidateRefresh(hashed, refresh string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(refresh)); err != nil {
		return false
	}
	return true
}

func (s *tokenService) CreateJTI() string {
	return uuid.NewString()
}
