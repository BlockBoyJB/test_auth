package v1

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
	"os"
)

func LoggingMiddleware(h *echo.Echo, output string) {
	cfg := middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339}", "method":"${method}","uri":"${uri}", "status":${status}, "error":"${error}"}` + "\n",
	}
	if output == "stdout" {
		cfg.Output = os.Stdout
	} else {
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Output = file
	}
	h.Use(middleware.LoggerWithConfig(cfg))
}
