package smtpmail

import (
	"context"
	_ "embed"

	"github.com/fahmifan/authme"
	"gopkg.in/gomail.v2"
)

var _ authme.Mailer = (*SMTP)(nil)

type Config struct {
	Host     string `json:"host" validate:"required"`
	Port     int    `json:"port" validate:"required"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type SMTP struct {
	mail *gomail.Dialer
	cfg  *Config
}

func NewSmtpClient(cfg *Config) (smtp *SMTP, err error) {
	smtp = &SMTP{
		cfg: cfg,
		mail: gomail.NewDialer(
			cfg.Host,
			cfg.Port,
			cfg.Username,
			cfg.Password,
		),
	}

	closer, err := smtp.mail.Dial()
	if err != nil {
		return nil, err
	}
	closer.Close()

	return smtp, nil
}

func (m *SMTP) Send(ctx context.Context, arg authme.MailerSendArg) (err error) {
	msg := gomail.NewMessage()
	msg.SetHeader("From", arg.From)
	msg.SetHeader("To", arg.To)
	msg.SetHeader("Subject", arg.Subject)
	msg.SetBody("text/html", arg.Subject)

	return m.mail.DialAndSend(msg)
}
