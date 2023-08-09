package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/backend/redis"
	"github.com/fahmifan/authme/backend/smtpmail"
	"github.com/fahmifan/authme/register"
	"github.com/go-chi/chi/v5"

	_ "github.com/lib/pq"
)

var httpserver *http.Server

func Stop(ctx context.Context) {
	httpserver.Shutdown(ctx)
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
		Port: 1025,
	})
	if err != nil {
		return fmt.Errorf("run: new smtp client: %w", err)
	}

	redisHost := "localhost:6379"

	guidGenerator := psql.UUIDGenerator{}
	passHasher := authme.DefaultPasswordHasher{}
	mailComposer := register.NewDefaultMailComposer("test@email.com")

	userRW := psql.NewUserReadWriter(db)
	retryCountRW := psql.NewRetryCountReadWriter(db)
	sessionRW := psql.NewSessionReadWriter(db)

	locker, err := redis.NewRedisLock(redisHost)
	if err != nil {
		return fmt.Errorf("run: new redis lock: %w", err)
	}

	auther := auth.NewAuth(auth.NewAuthArg{
		UserReader:     userRW,
		PasswordHasher: passHasher,
		RetryCountRW:   retryCountRW,
		Locker:         locker,
	})

	jwtauther := auth.NewJWTAuther(auth.NewJWTAutherArg{
		Auther:        auther,
		Secret:        []byte("secret"),
		SessionRW:     sessionRW,
		GUIDGenerator: guidGenerator,
	})

	registerer := register.NewRegister(register.NewRegisterArgs{
		VerificationBaseURL: "http://localhost:8080/verification",
		UserRW:              userRW,
		PasswordHasher:      passHasher,
		MailComposer:        mailComposer,
		GUIDGenerator:       guidGenerator,
		Locker:              locker,
		Mailer:              smtpMailer,
	})

	router := chi.NewRouter()

	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	router.Post("/auth", func(w http.ResponseWriter, r *http.Request) {
		req := struct {
			Email    string `json:"email" validate:"required,email"`
			Password string `json:"password" validate:"required,min=8,max=32"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := jwtauther.Auth(r.Context(), auth.AuthRequest{
			PID:           req.Email,
			PlainPassword: req.Password,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(res)
	})

	router.Post("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		req := struct {
			Email         string `json:"email" validate:"required,email"`
			PlainPassword string `json:"password" validate:"required,min=8,max=32"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := registerer.Register(r.Context(), register.RegisterRequest{
			PID:           req.Email,
			Email:         req.Email,
			PlainPassword: req.PlainPassword,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(res)
	})

	router.Get("/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		pid := r.URL.Query().Get("pid")
		token := r.URL.Query().Get("token")

		res, err := registerer.VerifyRegistration(r.Context(), register.VerifyRegistrationRequest{
			PID:         pid,
			VerifyToken: token,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(res)
		if err != nil {
			fmt.Println("encode err: ", err)
			return
		}
	})

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
