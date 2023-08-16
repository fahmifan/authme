package httphandler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/register"
	"github.com/go-chi/chi/v5"
)

const (
	PathHealthz        = "/healthz"
	PathRegister       = "/auth/register"
	PathVerifyRegister = "/auth/verify"
	PathRefreshToken   = "/auth/refresh"
	PathAuth           = "/auth"
)

type HttpError struct {
	Err  string `json:"error"`
	Code int    `json:"code"`
}

type AccountHandler struct {
	db                  *sql.DB
	locker              authme.Locker
	verificationBaseURL string
	mailComposer        register.RegisterMailComposer
	mailer              authme.Mailer
}

type NewAccountHandlerArg struct {
	VerificationBaseURL string
	DB                  *sql.DB
	MailComposer        register.RegisterMailComposer
	Locker              authme.Locker
	Mailer              authme.Mailer
}

func NewAccountHandler(arg NewAccountHandlerArg) *AccountHandler {
	return &AccountHandler{
		db:                  arg.DB,
		locker:              arg.Locker,
		mailComposer:        arg.MailComposer,
		verificationBaseURL: arg.VerificationBaseURL,
		mailer:              arg.Mailer,
	}
}

func (handler *AccountHandler) MigrateUp() error {
	if err := psql.MigrateUp(handler.db); err != nil {
		return fmt.Errorf("run: migrate up: %w", err)
	}

	return nil
}

func (handler *AccountHandler) AccountRouter(routePrefix string) (*chi.Mux, error) {
	passHasher := authme.DefaultPasswordHasher{}
	guidGenerator := psql.UUIDGenerator{}
	userRW := psql.NewUserReadWriter(handler.db)

	registerer := register.NewRegister(register.NewRegisterArgs{
		VerificationBaseURL: handler.verificationBaseURL,
		Locker:              handler.locker,
		UserRW:              userRW,
		PasswordHasher:      passHasher,
		MailComposer:        handler.mailComposer,
		GUIDGenerator:       guidGenerator,
		Mailer:              handler.mailer,
	})

	router := chi.NewRouter()

	router.Get(routePrefix+PathHealthz, handler.handleHelathz())
	router.Post(routePrefix+PathRegister, handler.handleRegister(registerer))
	router.Get(routePrefix+PathVerifyRegister, handler.handleVerifyRegistration(registerer))

	return router, nil
}

func (handler *AccountHandler) handleHelathz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(nil)
	}
}

func (handler *AccountHandler) handleRegister(registerer register.Register) http.HandlerFunc {
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

func (handler *AccountHandler) handleVerifyRegistration(registerer register.Register) http.HandlerFunc {
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
