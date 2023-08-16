package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/httphandler"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/backend/smtpmail"
	"github.com/fahmifan/authme/register"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"

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
	defer db.Close()

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

	mailComposer := register.NewDefaultMailComposer("app@example.com", "Authme")

	accountHandler := httphandler.NewAccountHandler(httphandler.NewAccountHandlerArg{
		VerificationBaseURL: "http://localhost:8080/verification",
		DB:                  db,
		MailComposer:        mailComposer,
		Mailer:              smtpMailer,
		Locker:              authme.NewDefaultLocker(),
	})

	if err := accountHandler.MigrateUp(); err != nil {
		return fmt.Errorf("run: migrate up: %w", err)
	}

	jwtAuthHandler := httphandler.NewJWTAuthHandler(httphandler.NewJWTAuthHandlerArg{
		JWTSecret:      []byte("secret"),
		RoutePrefix:    "/rest",
		AccountHandler: accountHandler,
	})

	cookieAuthHandler := httphandler.NewCookieAuthHandler(httphandler.NewCookieAuthHandlerArg{
		RoutePrefix:    "/cookie",
		AccountHandler: accountHandler,
		CookieDomain:   "localhost",
		CookieSecret:   securecookie.GenerateRandomKey(16),
	})

	cookieRouter, err := cookieAuthHandler.CookieAuthRouter()
	if err != nil {
		return fmt.Errorf("run: router: %w", err)
	}
	cookieMiddleware := cookieAuthHandler.Middleware()

	restRouter, err := jwtAuthHandler.JWTAuthRouter()
	if err != nil {
		return fmt.Errorf("run: router: %w", err)
	}

	router := chi.NewMux()
	router.Handle("/cookie*", cookieRouter)
	router.Handle("/rest*", restRouter)

	router.Group(func(r chi.Router) {
		r.With(cookieMiddleware.Authenticate()).Get("/private-cookie", handlePrivateCookie)
	})

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

func handlePrivateCookie(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok")
}
