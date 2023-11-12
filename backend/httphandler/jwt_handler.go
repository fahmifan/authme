package httphandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/go-chi/chi/v5"
)

type JWTAuthHandler struct {
	NewJWTAuthHandlerArg
}

type NewJWTAuthHandlerArg struct {
	JWTSecret    []byte
	RoutePrefix  string
	SecureCookie bool

	GUIDGenerator        authme.GUIDGenerator
	UserReadWriter       authme.UserReadWriter
	RetryCountReadWriter authme.RetryCountReadWriter
	SessionReadWriter    auth.SessionReadWriter
	AccountHandler       *AccountHandler
}

func NewJWTAuthHandler(arg NewJWTAuthHandlerArg) *JWTAuthHandler {
	return &JWTAuthHandler{
		NewJWTAuthHandlerArg: arg,
	}
}

func (handler *JWTAuthHandler) JWTAuthRouter() (*chi.Mux, error) {
	router, err := handler.AccountHandler.AccountRouter(handler.RoutePrefix)
	if err != nil {
		return nil, err
	}

	passHasher := authme.DefaultPasswordHasher{}

	guidGenerator := handler.GUIDGenerator
	userRW := handler.UserReadWriter
	retryCountRW := handler.RetryCountReadWriter
	sessionRW := handler.SessionReadWriter

	auther := auth.NewAuth(auth.NewAuthArg{
		UserReader:     userRW,
		PasswordHasher: passHasher,
		RetryCountRW:   retryCountRW,
	})

	jwtauther := auth.NewJWTAuther(auth.NewJWTAutherArg{
		Auther:        auther,
		Secret:        handler.JWTSecret,
		SessionRW:     sessionRW,
		GUIDGenerator: guidGenerator,
	})

	router.Post(handler.RoutePrefix+PathAuth, handler.handleAuth(jwtauther))
	router.Post(handler.RoutePrefix+PathRefreshToken, handler.handleRefreshingToken(jwtauther))
	router.Get(handler.RoutePrefix+PathNewAuth, handler.handleNewAuth())

	return router, nil
}

func (handler *JWTAuthHandler) handleNewAuth() http.HandlerFunc {
	tpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		panic(err)
	}

	type TplData struct {
		RegisterEndpoint string
		LoginEndpoint    template.JSStr
		CSRFTag          string
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tplData := TplData{
			RegisterEndpoint: handler.RoutePrefix + PathRegister,
			LoginEndpoint:    template.JSStr(handler.RoutePrefix + PathAuth),
		}

		err := tpl.ExecuteTemplate(w, "new_auth.html", tplData)
		if err != nil {
			fmt.Println("AccountHandler: handleNewAuth: ", err)
			return
		}
	}
}

type JWTAuthResponse struct {
	AccessToken   string    `json:"access_token"`
	ExpiredAt     int64     `json:"expired_at"`
	ExpiredAtTime time.Time `json:"-"`
}

const CookieRefreshToken = "refresh_token"

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

		authRes := auth.JWTAuthResponse{}
		lockKey := "jwt_handler:auth:email:" + req.Email
		err := handler.AccountHandler.Locker.Lock(r.Context(), lockKey, func(ctx context.Context) (err error) {
			authRes, err = jwtauther.Auth(r.Context(), handler.AccountHandler.DB, auth.AuthRequest{
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

		res := JWTAuthResponse{
			AccessToken:   authRes.AccessToken,
			ExpiredAt:     authRes.ExpiredAt,
			ExpiredAtTime: authRes.ExpiredAtTime,
		}

		writeJSON(w, http.StatusOK, res)
	}
}

func (handler *JWTAuthHandler) handleRefreshingToken(jwtauther auth.JWTAuther) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := getRefreshToken(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})

			return
		}

		authRes, err := jwtauther.RefreshToken(r.Context(), handler.AccountHandler.DB, refreshToken)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		res := JWTAuthResponse{
			AccessToken:   authRes.AccessToken,
			ExpiredAt:     authRes.ExpiredAt,
			ExpiredAtTime: authRes.ExpiredAtTime,
		}

		writeJSON(w, http.StatusOK, res)
	}
}

func getRefreshToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(CookieRefreshToken)
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

func setCookieRefreshToken(w http.ResponseWriter, secure bool, authRes auth.JWTAuthResponse) {
	cookie := http.Cookie{
		Name:     CookieRefreshToken,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Value:    authRes.RefreshToken,
		Expires:  authRes.ExpiredAtTime,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)
}

func (handler *JWTAuthHandler) Middleware() JWTAuthMiddleware {
	return JWTAuthMiddleware{
		accountHandler: handler.AccountHandler,
		jwtSecret:      handler.JWTSecret,
	}
}

type JWTAuthMiddleware struct {
	accountHandler *AccountHandler
	jwtSecret      []byte
}

func (mdw JWTAuthMiddleware) Authenticate() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessToken, err := mdw.getAccessToken(r)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err: err.Error(),
				})

				return
			}

			authUser, err := auth.VerifyAccessToken(mdw.jwtSecret, accessToken)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, HttpError{
					Err: err.Error(),
				})

				return
			}

			ctx := context.WithValue(r.Context(), UserCtxKey, authUser)
			*r = *(r.WithContext(ctx))

			next.ServeHTTP(w, r)
		})
	}
}

func (mdw JWTAuthMiddleware) getAccessToken(r *http.Request) (string, error) {
	// get from header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 {
		return "", errors.New("invalid authorization header")
	}

	if authHeaderParts[0] != "Bearer" {
		return "", errors.New("invalid authorization header")
	}

	return authHeaderParts[1], nil
}
