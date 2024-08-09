package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"net/netip"
	"test_auth/internal/repo"
	"test_auth/internal/repo/pgerrs"
	"test_auth/pkg/smtp"
	"time"
)

const (
	authServicePrefixLog = "/service/auth"
)

var defaultSignMethod = jwt.SigningMethodHS512

type TokenClaims struct {
	jwt.StandardClaims
	UserId   string `json:"user_id"`
	UserAddr string `json:"user_addr"`
}

type authService struct {
	user       repo.User
	smtp       smtp.Smtp
	signKey    []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func newAuthService(user repo.User, smtp smtp.Smtp, signKey string, accessTTL, refreshTTL time.Duration) *authService {
	return &authService{
		user:       user,
		smtp:       smtp,
		signKey:    []byte(signKey),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (s *authService) CreateTokens(ctx context.Context, remoteAddr, userId string) (string, string, error) {
	return s.newTokenPair(ctx, remoteAddr, userId)
}

func (s *authService) RefreshToken(ctx context.Context, remoteAddr, refreshToken string) (string, string, error) {
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		if errors.Is(err, ErrCannotParseToken) {
			return "", "", ErrCannotRefreshToken
		}
		return "", "", err
	}
	u, err := s.user.FindById(ctx, claims.UserId)
	if err != nil {
		if errors.Is(err, pgerrs.ErrNotFound) {
			return "", "", ErrUserNotFound
		}
		log.Errorf("%s/RefreshToken error find user: %s", authServicePrefixLog, err)
		return "", "", ErrCannotRefreshToken
	}

	refreshTokenShaSum := fmt.Sprintf("%x", sha256.Sum256([]byte(refreshToken)))
	if err = bcrypt.CompareHashAndPassword([]byte(u.RefreshToken), []byte(refreshTokenShaSum)); err != nil {
		return "", "", ErrInvalidToken
	}

	addr, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		log.Errorf("%s/RefreshToken error parse user addr: %s", authServicePrefixLog, err)
		return "", "", ErrCannotRefreshToken
	}
	if claims.UserAddr != addr.Addr().String() {
		// В реальности, конечно, тут отправляется сообщение в брокер
		go func() { _ = s.sendWarningMessage(addr.Addr().String(), u.Email) }()
		return "", "", errors.New("refresh operation from another addr")
	}

	access, refresh, err := s.newTokenPair(ctx, remoteAddr, claims.UserId)
	if err != nil {
		return "", "", ErrCannotRefreshToken
	}
	return access, refresh, nil
}

func (s *authService) newTokenPair(ctx context.Context, remoteAddr, userId string) (accessToken string, refreshToken string, err error) {
	accessToken, err = s.generateToken(remoteAddr, userId, s.accessTTL)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.generateToken(remoteAddr, userId, s.refreshTTL)
	if err != nil {
		return "", "", err
	}

	// обязательным условием является шифрование токена в бд именно через bcrypt. Однако jwt длиннее чем 72 байта, поэтому предварительно хэшируем sha256
	refreshTokenShaSum := fmt.Sprintf("%x", sha256.Sum256([]byte(refreshToken)))

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshTokenShaSum), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("%s/newTokenPair error create hash for refresh token: %s", authServicePrefixLog, err)
		return "", "", err
	}

	if err = s.user.UpdateToken(ctx, userId, string(hashedRefresh)); err != nil {
		if errors.Is(err, pgerrs.ErrNotFound) {
			return "", "", ErrUserNotFound
		}
		log.Errorf("%s/newTokenPair error update user refresh token: %s", authServicePrefixLog, err)
		return "", "", err
	}
	return
}

func (s *authService) generateToken(remoteAddr, userId string, ttl time.Duration) (string, error) {
	addr, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		log.Errorf("%s/generateToken error parse addr: %s", authServicePrefixLog, err)
		return "", err
	}
	token := jwt.NewWithClaims(defaultSignMethod, &TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ttl).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserId:   userId,
		UserAddr: addr.Addr().String(),
	})

	signedToken, err := token.SignedString(s.signKey)
	if err != nil {
		log.Errorf("%s/generateToken error sign token: %s", authServicePrefixLog, err)
		return "", err
	}
	return signedToken, nil
}

func (s *authService) parseToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrIncorrectSignMethod
		}
		return s.signKey, nil
	})
	if err != nil {
		if !errors.Is(err, ErrIncorrectSignMethod) {
			log.Errorf("%s/parseToken error parse token: %s", authServicePrefixLog, err)
			return nil, err
		}
		return nil, ErrCannotParseToken
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, ErrCannotParseToken
	}
	return claims, nil
}

func (s *authService) sendWarningMessage(addr, to string) error {
	const template = "Subject: Warning message\n\r" +
		"Hello from \"Company Name\"! We have noticed suspicious activity on your account. " +
		"Logged in at %s UTC from the address %s. If it's not you, change your password immediately"

	text := fmt.Sprintf(template, time.Now().UTC().Format("15:04:05 02.01.2006"), addr)

	if err := s.smtp.SendMail(to, text); err != nil {
		log.Errorf("%s/sendWarningMessage error send smtp message: %s", authServicePrefixLog, err)
		return err
	}
	return nil
}
