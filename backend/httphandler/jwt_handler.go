package httphandler

import (
	"context"
	"encoding/json"
	"errors"
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
	userRW := psql.NewUserReadWriter()
	retryCountRW := psql.NewRetryCountReadWriter()
	sessionRW := psql.NewSessionReadWriter()

	auther := auth.NewAuth(auth.NewAuthArg{
		UserReader:     userRW,
		PasswordHasher: passHasher,
		RetryCountRW:   retryCountRW,
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

		res := auth.JWTAuthResponse{}
		lockKey := "jwt_handler:auth:email:" + req.Email
		err := handler.accountHandler.locker.Lock(r.Context(), lockKey, func(ctx context.Context) (err error) {
			res, err = jwtauther.Auth(r.Context(), handler.accountHandler.db, auth.AuthRequest{
				PID:           req.Email,
				PlainPassword: req.Password,
			})
			return err
		})
		if err != nil {
			if errors.Is(err, authme.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, HttpError{
					Err: "not found",
				})
				return
			}

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

		res, err := jwtauther.RefreshToken(r.Context(), handler.accountHandler.db, req.RefreshToken)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, res)
	}
}
