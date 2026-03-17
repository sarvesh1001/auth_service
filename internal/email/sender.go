package email

import (
	"io"

	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
)

type Sender interface {
	Send(to, subject, body string, attachments ...Attachment) error
}

type Attachment struct {
	Filename string
	Data     []byte
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type smtpSender struct {
	config SMTPConfig
	logger *zap.Logger
}

func NewSMTPSender(cfg SMTPConfig, logger *zap.Logger) Sender {
	return &smtpSender{
		config: cfg,
		logger: logger.Named("email_sender"),
	}
}

func (s *smtpSender) Send(to, subject, body string, attachments ...Attachment) error {
	logger := s.logger.With(
		zap.String("to", to),
		zap.String("subject", subject),
		zap.String("from", s.config.From),
		zap.String("smtp_host", s.config.Host),
		zap.Int("smtp_port", s.config.Port),
		zap.String("smtp_username", s.config.Username),
	)
	logger.Debug("preparing to send email")

	m := gomail.NewMessage()
	m.SetHeader("From", s.config.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	for _, att := range attachments {
		logger.Debug("attaching file", zap.String("filename", att.Filename), zap.Int("size_bytes", len(att.Data)))
		m.Attach(att.Filename,
			gomail.SetCopyFunc(func(w io.Writer) error {
				_, err := w.Write(att.Data)
				return err
			}),
		)
	}

	d := gomail.NewDialer(s.config.Host, s.config.Port, s.config.Username, s.config.Password)
	logger.Debug("dialing SMTP server")

	if err := d.DialAndSend(m); err != nil {
		logger.Error("failed to send email", zap.Error(err))
		return err
	}

	logger.Info("email sent successfully")
	return nil
}
