package v1

import (
	"errors"
	"github.com/labstack/echo/v4"
)

func errorResponse(c echo.Context, status int, err error) {
	var HTTPError *echo.HTTPError
	if ok := errors.As(err, &HTTPError); !ok {
		err = echo.NewHTTPError(status, err.Error())
	}
	_ = c.JSON(status, err)
}
