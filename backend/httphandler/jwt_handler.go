package httphandler

import (
	"encoding/json"
	"net/http"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/go-chi/chi/v5"
)

type JWTAuthHandler struct {
	accountHandler *AccountHandler
	jwtSecret      []byte
	routePrefix    string
}

type NewJWTAuthHandlerArg struct {
	JWTSecret      []byte
	RoutePrefix    string
	AccountHandler *AccountHandler
}

func NewJWTAuthHandler(arg NewJWTAuthHandlerArg) *JWTAuthHandler {
	return &JWTAuthHandler{
		accountHandler: arg.AccountHandler,
		routePrefix:    arg.RoutePrefix,
		jwtSecret:      arg.JWTSecret,
	}
}

func (handler *JWTAuthHandler) JWTAuthRouter() (*chi.Mux, error) {
	router, err := handler.accountHandler.AccountRouter(handler.routePrefix)
	if err != nil {
		return nil, err
	}

	passHasher := authme.DefaultPasswordHasher{}

	guidGenerator := psql.UUIDGenerator{}
	userRW := psql.NewUserReadWriter(handler.accountHandler.db)
	retryCountRW := psql.NewRetryCountReadWriter(handler.accountHandler.db)
	sessionRW := psql.NewSessionReadWriter(handler.accountHandler.db)

	auther := auth.NewAuth(auth.NewAuthArg{
		UserReader:     userRW,
		PasswordHasher: passHasher,
		RetryCountRW:   retryCountRW,
		Locker:         handler.accountHandler.locker,
	})

	jwtauther := auth.NewJWTAuther(auth.NewJWTAutherArg{
		Auther:        auther,
		Secret:        handler.jwtSecret,
		SessionRW:     sessionRW,
		GUIDGenerator: guidGenerator,
	})

	router.Post(handler.routePrefix+PathAuth, handler.handleAuth(jwtauther))
	router.Post(handler.routePrefix+PathRefreshToken, handler.handleRefreshingToken(jwtauther))

	return router, nil
}

func (handler *JWTAuthHandler) handleAuth(jwtauther auth.JWTAuther) http.HandlerFunc {
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

func (handler *JWTAuthHandler) handleRefreshingToken(jwtauther auth.JWTAuther) http.HandlerFunc {
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
