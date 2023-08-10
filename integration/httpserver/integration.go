package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/fahmifan/authme/backend/httphandler"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/backend/smtpmail"
	"github.com/fahmifan/authme/register"

	_ "github.com/lib/pq"
)

var httpserver *http.Server

func Stop(ctx context.Context) {
	if httpserver != nil {
		httpserver.Shutdown(ctx)
	}
}

// use all default implementation
func Run() error {
	db, err := sql.Open("postgres", "postgres://root:root@localhost:5432/authme?sslmode=disable")
	if err != nil {
		return fmt.Errorf("run: open db: %w", err)
	}

	if err := psql.MigrateUp(db); err != nil {
		return fmt.Errorf("run: migrate up: %w", err)
	}

	smtpMailer, err := smtpmail.NewSmtpClient(&smtpmail.Config{
		Host: "localhost",
		Port: 1025, // mailhog
	})
	if err != nil {
		return fmt.Errorf("run: new smtp client: %w", err)
	}

	redisHost := "localhost:6379"

	handler := httphandler.NewHTTPHandler(httphandler.NewHTTPHandlerArg{
		RedisHost:           redisHost,
		JWTSecret:           []byte("secret"),
		VerificationBaseURL: "http://localhost:8080/verification",
		DB:                  db,
		MailComposer:        register.NewDefaultMailComposer("app@example.com", "Authme"),
		Mailer:              smtpMailer,
	})

	router, err := handler.Router()
	if err != nil {
		return fmt.Errorf("run: router: %w", err)
	}

	fmt.Println("listen on :8080")
	httpserver = &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	err = httpserver.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("run: listen and serve: %w", err)
	}

	return nil
}
