package smtp

import (
	"net"
	"net/smtp"
)

const (
	defaultHost = "smtp.gmail.com"
	defaultPort = "587"
)

type Smtp interface {
	SendMail(to, text string) error
}

type client struct {
	auth   smtp.Auth
	sender string
	host   string
	port   string
}

func NewSmtp(login, password string) Smtp {
	return &client{
		auth:   smtp.PlainAuth("", login, password, defaultHost),
		sender: login,
		host:   defaultHost,
		port:   defaultPort,
	}
}

func (c *client) SendMail(to, text string) error {
	return smtp.SendMail(net.JoinHostPort(c.host, c.port), c.auth, c.sender, []string{to}, []byte(text))
}
