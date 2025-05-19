package v1

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
	"test_auth/internal/service"
)

type authRouter struct {
	auth service.Auth
}

func newAuthRouter(g *echo.Group, auth service.Auth) {
	r := &authRouter{
		auth: auth,
	}

	g.POST("/sign-in", r.signIn)
	g.POST("/refresh", r.refresh)
	g.GET("/me", r.getID)
	g.GET("/logout", r.logout)
}

type authSignInInput struct {
	Id string `json:"id" validate:"required"`
}

//	@Summary		Sign In
//	@Description	Auth user, get access and refresh tokens
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			input	body		authSignInInput	true	"input"
//	@Success		200		{object}	service.TokenOutput
//	@Failure		400		{string}	string	"Bad Request"
//	@Failure		403		{string}	string	"Forbidden"
//	@Failure		500		{string}	string	"Internal Server Error"
//	@Router			/api/v1/auth/sign-in [post]
func (r *authRouter) signIn(c echo.Context) error {
	var input authSignInInput

	if err := c.Bind(&input); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := c.Validate(&input); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	to, err := r.auth.SignIn(c.Request().Context(), service.TokenInput{
		UserId:    input.Id,
		UserAgent: c.Request().UserAgent(),
		IP:        c.RealIP(),
	})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, to)
}

type authRefreshInput struct {
	Access  string `json:"access" validate:"required"`
	Refresh string `json:"refresh" validate:"required"`
}

//	@Summary		Refresh
//	@Description	Refresh operation for access and refresh pair tokens
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			input	body		authRefreshInput	true	"input"
//	@Success		200		{object}	service.TokenOutput
//	@Failure		400		{string}	string	"Bad Request"
//	@Failure		403		{string}	string	"Forbidden"
//	@Failure		500		{string}	string	"Internal Server Error"
//	@Router			/api/v1/auth/refresh [post]
func (r *authRouter) refresh(c echo.Context) error {
	var input authRefreshInput

	if err := c.Bind(&input); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := c.Validate(&input); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}

	to, err := r.auth.Refresh(c.Request().Context(), service.RefreshInput{
		Access:    input.Access,
		Refresh:   input.Refresh,
		UserAgent: c.Request().UserAgent(),
		IP:        c.RealIP(),
	})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, to)
}

type authGetIDOutput struct {
	Id string `json:"user_id"`
}

//	@Summary		Get ID
//	@Description	Get user id from access token. Access token must be valid
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	authGetIDOutput
//	@Failure		401	{string}	string	"Unauthorized"
//	@Failure		403	{string}	string	"Forbidden"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Security		BearerAuth
//	@Router			/api/v1/auth/me [get]
func (r *authRouter) getID(c echo.Context) error {
	token, ok := parseToken(c.Request())
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	id, err := r.auth.GetID(c.Request().Context(), token)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, authGetIDOutput{
		Id: id,
	})
}

//	@Summary		Log out
//	@Description	Log out operation makes a pair of access and refresh tokens invalid
//	@Tags			auth
//	@Success		200	{string}	string	"OK"
//	@Failure		401	{string}	string	"Unauthorized"
//	@Failure		403	{string}	string	"Forbidden"
//	@Failure		500	{string}	string	"Internal Server Error"
//	@Security		BearerAuth
//	@Router			/api/v1/auth/logout [get]
func (r *authRouter) logout(c echo.Context) error {
	token, ok := parseToken(c.Request())
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}

	if err := r.auth.Logout(c.Request().Context(), token); err != nil {
		return err
	}
	return c.NoContent(http.StatusOK)
}

func parseToken(r *http.Request) (string, bool) {
	header := r.Header.Get(echo.HeaderAuthorization)
	if header == "" {
		return "", false
	}
	token := strings.Split(header, "Bearer ")
	if len(token) != 2 {
		return "", false
	}
	if len(token[1]) == 0 {
		return "", false
	}
	return token[1], true
}
