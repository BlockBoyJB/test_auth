package v1

import (
	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
	_ "test_auth/docs"
	"test_auth/internal/service"
)

func NewRouter(g *echo.Echo, services *service.Services) {
	g.Use(errorMiddleware)

	g.GET("/ping", ping)
	g.GET("/swagger/*", echoSwagger.WrapHandler)

	v1 := g.Group("/api/v1")

	newAuthRouter(v1.Group("/auth"), services.Auth)

	newWebhookRouter(v1.Group("/webhook"))
}

func ping(c echo.Context) error {
	return c.NoContent(200)
}
