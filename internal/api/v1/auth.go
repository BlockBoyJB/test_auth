package v1

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"test_auth/internal/service"
)

type authRouter struct {
	auth service.Auth
	user service.User
}

func newAuthRouter(g *echo.Group, auth service.Auth, user service.User) {
	r := &authRouter{
		auth: auth,
		user: user,
	}

	g.POST("/sign-up", r.signUp)
	g.POST("/sign-in", r.signIn)
	g.POST("/refresh", r.refresh)
}

type signUpInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (r *authRouter) signUp(c echo.Context) error {
	var input signUpInput

	if err := c.Bind(&input); err != nil {
		errorResponse(c, http.StatusBadRequest, echo.ErrBadRequest)
		return nil
	}
	if err := c.Validate(input); err != nil {
		errorResponse(c, http.StatusBadRequest, err)
		return nil
	}

	userId, err := r.user.Create(c.Request().Context(), service.UserCreateInput{
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrUserAlreadyExists) {
			errorResponse(c, http.StatusBadRequest, err)
			return nil
		}
		errorResponse(c, http.StatusInternalServerError, echo.ErrInternalServerError)
		return err
	}

	type response struct {
		UserId string `json:"user_id"`
	}
	return c.JSON(http.StatusCreated, response{UserId: userId})
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type signInInput struct {
	UserId   string `json:"user_id" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (r *authRouter) signIn(c echo.Context) error {
	var input signInInput

	if err := c.Bind(&input); err != nil {
		errorResponse(c, http.StatusBadRequest, echo.ErrBadRequest)
		return nil
	}
	if err := c.Validate(input); err != nil {
		errorResponse(c, http.StatusBadRequest, err)
		return nil
	}

	ok, err := r.user.Verify(c.Request().Context(), input.UserId, input.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			errorResponse(c, http.StatusBadRequest, err)
			return nil
		}
		errorResponse(c, http.StatusInternalServerError, echo.ErrInternalServerError)
		return err
	}
	if !ok {
		errorResponse(c, http.StatusForbidden, echo.ErrForbidden)
		return nil
	}

	access, refresh, err := r.auth.CreateTokens(c.Request().Context(), c.Request().RemoteAddr, input.UserId)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, echo.ErrInternalServerError)
		return err
	}
	return c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

type refreshInput struct {
	Token string `json:"token" validate:"required"`
}

func (r *authRouter) refresh(c echo.Context) error {
	var input refreshInput

	if err := c.Bind(&input); err != nil {
		errorResponse(c, http.StatusBadRequest, echo.ErrBadRequest)
		return nil
	}
	if err := c.Validate(input); err != nil {
		errorResponse(c, http.StatusBadRequest, err)
		return nil
	}

	access, refresh, err := r.auth.RefreshToken(c.Request().Context(), c.Request().RemoteAddr, input.Token)
	if err != nil {
		if errors.Is(err, service.ErrCannotRefreshToken) {
			errorResponse(c, http.StatusInternalServerError, echo.ErrInternalServerError)
			return err
		}
		errorResponse(c, http.StatusBadRequest, err)
		return nil
	}

	return c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}
