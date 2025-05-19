package v1

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"test_auth/internal/service"
)

func errorMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err == nil {
			return nil
		}

		switch {
		case errors.Is(err, service.ErrInvalidToken), errors.Is(err, service.ErrInvalidUserAgent):

			return c.NoContent(http.StatusForbidden)

		default:
			return c.NoContent(http.StatusInternalServerError)
		}
	}
}
