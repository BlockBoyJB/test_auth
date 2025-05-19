package v1

import (
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"net/http"
	"time"
)

type webhookRouter struct{}

func newWebhookRouter(g *echo.Group) {
	r := &webhookRouter{}

	g.POST("", r.accept)
}

type webhookInput struct {
	UserId    string    `json:"user_id" validate:"required"`
	NewIP     string    `json:"new_ip" validate:"required"`
	OldIP     string    `json:"old_ip" validate:"required"`
	UserAgent string    `json:"user_agent" validate:"required"`
	Timestamp time.Time `json:"timestamp" validate:"required"`
}

func (r *webhookRouter) accept(c echo.Context) error {
	var input webhookInput

	if err := c.Bind(&input); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := c.Validate(&input); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}

	log.Info().Msgf("[WEBHOOK] %+v", input) // просто в лог

	return c.NoContent(http.StatusOK)
}
