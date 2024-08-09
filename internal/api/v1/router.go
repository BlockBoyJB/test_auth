package v1

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"test_auth/internal/service"
)

func NewRouter(h *echo.Echo, services *service.Services) {
	h.Use(middleware.Recover())
	h.GET("/ping", ping)

	v1 := h.Group("/api/v1")
	newAuthRouter(v1.Group("/auth"), services.Auth, services.User)
}

func ping(c echo.Context) error {
	return c.NoContent(200)
}
