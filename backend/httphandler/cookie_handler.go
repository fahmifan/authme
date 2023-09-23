package httphandler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

const UserAuthSessionKey = "user_auth"
const SessionStoreKey = "user_session"

type CookieAuthHandler struct {
	NewCookieAuthHandlerArg
	sessionStore sessions.Store
}

type NewCookieAuthHandlerArg struct {
	AccountHandler *AccountHandler
	CookieDomain   string
	RoutePrefix    string
	CookieSecret   []byte
	SecureCookie   bool

	redirectAfterLogin func(http.ResponseWriter, *http.Request)
	csrfProtect        func(http.Handler) http.Handler
}

func NewCookieAuthHandler(arg NewCookieAuthHandlerArg) *CookieAuthHandler {
	return &CookieAuthHandler{NewCookieAuthHandlerArg: arg}
}

func (handler *CookieAuthHandler) MigrateUp() error {
	if err := psql.MigrateUp(handler.AccountHandler.DB); err != nil {
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

	handler.csrfProtect = csrfProtect(handler.CookieSecret, handler.SecureCookie)

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

	handler.sessionStore = sessions.NewCookieStore(handler.CookieSecret)

	router, err := handler.AccountHandler.AccountRouter(handler.RoutePrefix)
	if err != nil {
		return nil, fmt.Errorf("router: %w", err)
	}

	router.With(handler.csrfProtect).Post(handler.RoutePrefix+PathAuth,
		handler.handleAuth(sessionAuther, handler.sessionStore),
	)
	router.With(handler.csrfProtect).Get(handler.RoutePrefix+PathCSRFToken, handler.handleCSRF())
	router.With(handler.csrfProtect).Get(handler.RoutePrefix+PathNewAuth, handler.handleNewAuth())

	return router, nil
}

func (handler *CookieAuthHandler) handleNewAuth() http.HandlerFunc {
	tpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		panic(err)
	}

	type TplData struct {
		RegisterEndpoint string
		LoginEndpoint    template.JSStr
		CSRFTag          template.JSStr
		CSRFTemplate     template.HTML
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tplData := TplData{
			RegisterEndpoint: handler.RoutePrefix + PathNewRegister,
			LoginEndpoint:    template.JSStr(handler.RoutePrefix + PathAuth),
			CSRFTag:          template.JSStr(csrf.Token(r)),
			CSRFTemplate:     csrf.TemplateField(r),
		}

		err := tpl.ExecuteTemplate(w, "new_cookie_auth.html", tplData)
		if err != nil {
			fmt.Println("AccountHandler: handleNewAuth: ", err)
			return
		}
	}
}

func (handler *CookieAuthHandler) SetRedirectAfterLogin(fn func(http.ResponseWriter, *http.Request)) {
	handler.redirectAfterLogin = fn
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

		switch r.Header.Get("Content-Type") {
		case "application/json":
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, HttpError{
					Err: err.Error(),
				})

				return
			}
		case "application/x-www-form-urlencoded":
			req.Email = r.FormValue("email")
			req.Password = r.FormValue("password")
		default:
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: "invalid content type",
			})
			return
		}

		sess := auth.SessionAuthResponse{}
		lockKey := "cookie_handler:auth:email:" + req.Email
		err := handler.AccountHandler.Locker.Lock(r.Context(), lockKey, func(ctx context.Context) (err error) {
			sess, err = sessionAuther.Auth(r.Context(), handler.AccountHandler.DB, auth.AuthRequest{
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
		httpSess.Options.Domain = handler.CookieDomain
		httpSess.Values[UserAuthSessionKey] = sessJSON
		httpSess.Options.MaxAge = sess.MaxAge
		httpSess.Options.SameSite = http.SameSiteDefaultMode
		httpSess.Options.Secure = handler.SecureCookie
		httpSess.Options.Path = "/"

		if err := httpSess.Save(r, w); err != nil {
			writeJSON(w, http.StatusInternalServerError, HttpError{
				Err: err.Error(),
			})

			return
		}

		if handler.redirectAfterLogin != nil {
			handler.redirectAfterLogin(w, r)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"message": "success",
		})
	}
}

func (handler *CookieAuthHandler) handleCSRF() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"csrf": csrf.Token(r),
		})
	}
}

func (handler *CookieAuthHandler) Middleware() *CookieMiddleware {
	return &CookieMiddleware{
		sessionStore:  handler.sessionStore,
		sessionReader: psql.NewSessionReadWriter(),
		db:            handler.AccountHandler.DB,
		csrfProtect:   handler.csrfProtect,
	}
}

type CookieMiddleware struct {
	sessionStore  sessions.Store
	sessionReader auth.SessionReader
	db            *sql.DB
	csrfProtect   func(http.Handler) http.Handler
}

type Ctx string

const UserCtxKey Ctx = "user_ctx_key"
const CSRFHeader = "X-Csrf-Token"

func (mdw CookieMiddleware) SetAuthUserToCtx() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookieSess, _ := mdw.sessionStore.Get(r, SessionStoreKey)

			sessAuthBuf, ok := cookieSess.Values[UserAuthSessionKey].([]byte)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			sessAuth := auth.SessionAuthResponse{}
			err := json.Unmarshal(sessAuthBuf, &sessAuth)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			sess, err := mdw.sessionReader.FindByToken(
				r.Context(),
				mdw.db,
				sessAuth.Token,
			)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			if sess.IsExpired(time.Now()) {
				next.ServeHTTP(w, r)
				return
			}

			ctx := setUser(r.Context(), sess.User)
			*r = *(r.WithContext(ctx))

			next.ServeHTTP(w, r)
		})
	}
}

func (mdw CookieMiddleware) Authenticate() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			_, ok := GetUser(r.Context())
			if !ok {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err: "unauthorized",
				})

				return
			}

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

func (mdw CookieMiddleware) CSRF() func(http.Handler) http.Handler {
	return mdw.csrfProtect
}

func csrfProtect(secret []byte, secure bool) func(http.Handler) http.Handler {
	return csrf.Protect(
		secret,
		csrf.SameSite(csrf.SameSiteDefaultMode),
		csrf.Path("/"),
		csrf.Secure(secure),
		csrf.RequestHeader(CSRFHeader),
	)
}

func GetUser(ctx context.Context) (auth.UserSession, bool) {
	val := ctx.Value(UserCtxKey)
	if val == nil {
		return auth.UserSession{}, false
	}

	user, ok := val.(auth.UserSession)
	return user, ok
}

func setUser(ctx context.Context, user auth.UserSession) context.Context {
	return context.WithValue(ctx, UserCtxKey, user)
}
