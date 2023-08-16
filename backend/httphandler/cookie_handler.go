package httphandler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/gorilla/sessions"
)

const UserAuthSessionKey = "user_auth"
const SessionStoreKey = "user_session"

type CookieAuthHandler struct {
	accountHandler *AccountHandler
	routePrefix    string
	cokieDomain    string
	cookieSecret   []byte
	sessionStore   sessions.Store
}

type NewCookieAuthHandlerArg struct {
	AccountHandler *AccountHandler
	CookieDomain   string
	RoutePrefix    string
	CookieSecret   []byte
}

func NewCookieAuthHandler(arg NewCookieAuthHandlerArg) *CookieAuthHandler {
	return &CookieAuthHandler{
		accountHandler: arg.AccountHandler,
		routePrefix:    arg.RoutePrefix,
		cokieDomain:    arg.CookieDomain,
		cookieSecret:   arg.CookieSecret,
	}
}

func (handler *CookieAuthHandler) MigrateUp() error {
	if err := psql.MigrateUp(handler.accountHandler.db); err != nil {
		return fmt.Errorf("run: migrate up: %w", err)
	}

	return nil
}

func (handler *CookieAuthHandler) CookieAuthRouter() (http.Handler, error) {
	passHasher := authme.DefaultPasswordHasher{}

	userRW := psql.NewUserReadWriter()
	retryCountRW := psql.NewRetryCountReadWriter()
	sessionRW := psql.NewSessionReadWriter()
	guidGenerator := psql.UUIDGenerator{}

	auther := auth.NewAuth(auth.NewAuthArg{
		UserReader:     userRW,
		PasswordHasher: passHasher,
		RetryCountRW:   retryCountRW,
	})

	sessionAuther := auth.NewSessionAuther(auth.NewSessionAutherArg{
		Auther:        auther,
		SessionRW:     sessionRW,
		GUIDGenerator: guidGenerator,
	})

	handler.sessionStore = sessions.NewCookieStore(handler.cookieSecret)

	router, err := handler.accountHandler.AccountRouter(handler.routePrefix)
	if err != nil {
		return nil, fmt.Errorf("router: %w", err)
	}

	router.Post(handler.routePrefix+PathAuth, handler.handleAuth(sessionAuther, handler.sessionStore))

	return router, nil
}

func (handler *CookieAuthHandler) handleAuth(
	sessionAuther auth.SessionAuther,
	sessionStore sessions.Store,
) http.HandlerFunc {
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

		sess := auth.SessionAuthResponse{}
		lockKey := "cookie_handler:auth:email:" + req.Email
		err := handler.accountHandler.locker.Lock(r.Context(), lockKey, func(ctx context.Context) (err error) {
			sess, err = sessionAuther.Auth(r.Context(), handler.accountHandler.db, auth.AuthRequest{
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

		sessJSON, err := json.Marshal(sess)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, HttpError{
				Err: "cannot marshal session",
			})

			return
		}

		httpSess, _ := sessionStore.Get(r, SessionStoreKey)
		httpSess.Options.Domain = handler.cokieDomain
		httpSess.Values[UserAuthSessionKey] = sessJSON
		httpSess.Options.MaxAge = sess.MaxAge
		httpSess.Options.SameSite = http.SameSiteDefaultMode
		httpSess.Options.Path = "/"

		if err := httpSess.Save(r, w); err != nil {
			writeJSON(w, http.StatusInternalServerError, HttpError{
				Err: err.Error(),
			})

			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"message": "success",
		})
	}
}

func (handler *CookieAuthHandler) Middleware() *CookieMiddleware {
	return &CookieMiddleware{
		sessionStore:  handler.sessionStore,
		sessionReader: psql.NewSessionReadWriter(),
		db:            handler.accountHandler.db,
	}
}

type CookieMiddleware struct {
	sessionStore  sessions.Store
	sessionReader auth.SessionReader
	db            *sql.DB
}

type Ctx string

const UserCtxKey Ctx = "user_ctx_key"

func (cookieMiddleware CookieMiddleware) Authenticate() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			cookieSess, _ := cookieMiddleware.sessionStore.Get(r, SessionStoreKey)

			sessAuthBuf, ok := cookieSess.Values[UserAuthSessionKey].([]byte)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err:  "unauthorized",
					Code: http.StatusUnauthorized,
				})
				return
			}

			sessAuth := auth.SessionAuthResponse{}
			err := json.Unmarshal(sessAuthBuf, &sessAuth)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err: err.Error(),
				})

				return
			}

			sess, err := cookieMiddleware.sessionReader.FindByToken(
				r.Context(),
				cookieMiddleware.db,
				sessAuth.Token,
			)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err: err.Error(),
				})
				return
			}

			if sess.IsExpired(time.Now()) {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err: "expired",
				})
				return
			}

			ctx := context.WithValue(r.Context(), UserCtxKey, sess.User)
			*r = *(r.WithContext(ctx))

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
