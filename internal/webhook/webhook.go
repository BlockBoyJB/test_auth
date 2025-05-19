package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Webhook interface {
	Request(v Body) error
}

type webhookService struct {
	client *http.Client
	url    string
}

func NewWebhook(url string) Webhook {
	return &webhookService{
		client: http.DefaultClient,
		url:    url,
	}
}

type Body struct {
	UserId    string    `json:"user_id"`
	NewIP     string    `json:"new_ip"`
	OldIP     string    `json:"old_ip"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
}

func (s *webhookService) Request(v Body) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}

	r, err := http.NewRequest(http.MethodPost, s.url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}
