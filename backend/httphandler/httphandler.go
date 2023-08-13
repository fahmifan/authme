package httphandler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/backend/redis"
	"github.com/fahmifan/authme/register"
	"github.com/go-chi/chi/v5"
)

const (
	PathHealthz        = "/healthz"
	PathRegister       = "/auth/register"
	PathVerifyRegister = "/auth/verify"
	PathAuth           = "/auth"
	PathRefreshToken   = "/auth/refresh"
)

type HttpError struct {
	Err  string `json:"error"`
	Code int    `json:"code"`
}

type HTTPHandler struct {
	db                  *sql.DB
	redisHost           string
	jwtSecret           []byte
	verificationBaseURL string
	mailComposer        register.RegisterMailComposer
	mailer              authme.Mailer
}

type NewHTTPHandlerArg struct {
	RedisHost           string
	JWTSecret           []byte
	VerificationBaseURL string
	DB                  *sql.DB
	MailComposer        register.RegisterMailComposer
	Mailer              authme.Mailer
}

func NewHTTPHandler(arg NewHTTPHandlerArg) *HTTPHandler {
	return &HTTPHandler{
		db:                  arg.DB,
		redisHost:           arg.RedisHost,
		jwtSecret:           arg.JWTSecret,
		mailComposer:        arg.MailComposer,
		verificationBaseURL: arg.VerificationBaseURL,
		mailer:              arg.Mailer,
	}
}

func (handler *HTTPHandler) MigrateUp() error {
	if err := psql.MigrateUp(handler.db); err != nil {
		return fmt.Errorf("run: migrate up: %w", err)
	}

	return nil
}

func (handler *HTTPHandler) Router() (http.Handler, error) {
	db := handler.db

	guidGenerator := psql.UUIDGenerator{}
	passHasher := authme.DefaultPasswordHasher{}

	userRW := psql.NewUserReadWriter(db)
	retryCountRW := psql.NewRetryCountReadWriter(db)
	sessionRW := psql.NewSessionReadWriter(db)

	locker, err := redis.NewRedisLock(handler.redisHost)
	if err != nil {
		return nil, fmt.Errorf("run: new redis lock: %w", err)
	}

	auther := auth.NewAuth(auth.NewAuthArg{
		UserReader:     userRW,
		PasswordHasher: passHasher,
		RetryCountRW:   retryCountRW,
		Locker:         locker,
	})

	jwtauther := auth.NewJWTAuther(auth.NewJWTAutherArg{
		Auther:        auther,
		Secret:        handler.jwtSecret,
		SessionRW:     sessionRW,
		GUIDGenerator: guidGenerator,
	})

	registerer := register.NewRegister(register.NewRegisterArgs{
		VerificationBaseURL: handler.verificationBaseURL,
		Locker:              locker,
		UserRW:              userRW,
		PasswordHasher:      passHasher,
		MailComposer:        handler.mailComposer,
		GUIDGenerator:       guidGenerator,
		Mailer:              handler.mailer,
	})

	router := chi.NewRouter()

	router.Get(PathHealthz, handler.handleHelathz())
	router.Post(PathRegister, handler.handleRegister(registerer))
	router.Get(PathVerifyRegister, handler.handleVerifyRegistration(registerer))
	router.Post(PathAuth, handler.handleAuth(jwtauther))
	router.Post(PathRefreshToken, handler.handleRefreshingToken(jwtauther))

	return router, nil
}

func (handler *HTTPHandler) handleHelathz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(nil)
	}
}

func (handler *HTTPHandler) handleRegister(registerer register.Register) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := struct {
			Name            string `json:"name" validate:"required"`
			Email           string `json:"email" validate:"required,email"`
			PlainPassword   string `json:"password" validate:"required,min=8"`
			ConfirmPassword string `json:"confirmPassword" validate:"required,min=8"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		res, err := registerer.Register(r.Context(), register.RegisterRequest{
			PID:             req.Email,
			Name:            req.Name,
			Email:           req.Email,
			PlainPassword:   req.PlainPassword,
			ConfirmPassword: req.ConfirmPassword,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, res)
	}
}

func (handler *HTTPHandler) handleVerifyRegistration(registerer register.Register) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		writeJSON(w, http.StatusOK, res)
	}
}

func (handler *HTTPHandler) handleAuth(jwtauther auth.JWTAuther) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := struct {
			Email    string `json:"email" validate:"required,email"`
			Password string `json:"password" validate:"required,min=8,max=32"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})

			return
		}

		res, err := jwtauther.Auth(r.Context(), auth.AuthRequest{
			PID:           req.Email,
			PlainPassword: req.Password,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, res)
	}
}

func (handler *HTTPHandler) handleRefreshingToken(jwtauther auth.JWTAuther) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := struct {
			RefreshToken string `json:"refresh_token" validate:"required"`
		}{}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
		}

		res, err := jwtauther.RefreshToken(r.Context(), req.RefreshToken)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, res)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
