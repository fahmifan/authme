package httphandler

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/register"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
)

const (
	PathHealthz        = "/healthz"
	PathRegister       = "/auth/register"
	PathNewRegister    = "/auth/register/new"
	PathVerifyRegister = "/auth/verify"
	PathRefreshToken   = "/auth/refresh"
	PathAuth           = "/auth"
	PathNewAuth        = "/auth/new"
	PathCSRFToken      = "/auth/csrf"
)

type Ctx string

const UserCtxKey Ctx = "user_ctx_key"

type HttpError struct {
	Err  string `json:"error"`
	Code int    `json:"code"`
}

type NewAccountHandlerArg struct {
	VerificationBaseURL string
	RegisterRedirectURL string
	CSRFSecret          []byte
	CSRFSecure          bool

	DB             *sql.DB
	GUIDGenerator  authme.GUIDGenerator
	UserReadWriter authme.UserReadWriter
	MailComposer   register.RegisterMailComposer
	Mailer         authme.Mailer
	Locker         authme.Locker
}

type AccountHandler struct {
	NewAccountHandlerArg

	registerer register.Register
}

func NewAccountHandler(arg NewAccountHandlerArg) *AccountHandler {
	if arg.Locker == nil {
		arg.Locker = authme.NewDefaultLocker()
	}

	return &AccountHandler{NewAccountHandlerArg: arg}
}

func (handler *AccountHandler) AccountRouter(routePrefix string) (*chi.Mux, error) {
	passHasher := authme.DefaultPasswordHasher{}
	userRW := handler.UserReadWriter

	csrfMdw := csrf.Protect(
		handler.CSRFSecret,
		csrf.SameSite(csrf.SameSiteDefaultMode),
		csrf.Secure(handler.CSRFSecure),
		csrf.RequestHeader("x-csrf-token"),
	)

	handler.registerer = register.NewRegister(register.NewRegisterArgs{
		VerificationBaseURL: handler.VerificationBaseURL,
		UserRW:              userRW,
		PasswordHasher:      passHasher,
		MailComposer:        handler.MailComposer,
		GUIDGenerator:       handler.GUIDGenerator,
		Mailer:              handler.Mailer,
	})

	router := chi.NewRouter()

	router.Get(routePrefix+PathHealthz, handler.handleHelathz())
	router.With(csrfMdw).Get(routePrefix+PathNewRegister, handler.handleNewRegister(routePrefix))
	router.With(csrfMdw).Post(routePrefix+PathRegister, handler.handleRegister())
	router.Get(routePrefix+PathVerifyRegister, handler.handleVerifyRegistration())
	router.With(csrfMdw).Get(routePrefix+PathCSRFToken, handler.handleCSRFToken())

	return router, nil
}

func (handler *AccountHandler) handleHelathz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(nil)
	}
}

func (handler *AccountHandler) handleCSRFToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"csrf_token": csrf.Token(r),
		})
	}
}

//go:embed templates
var templateFS embed.FS

func (handler *AccountHandler) handleNewRegister(routePrefix string) http.HandlerFunc {
	tpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		panic(err)
	}

	type TplData struct {
		RegisterEndpoint template.JSStr
		LoginEndpoint    string
		CSRFTag          template.JSStr
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tplData := TplData{
			RegisterEndpoint: template.JSStr(routePrefix + PathRegister),
			LoginEndpoint:    routePrefix + PathAuth + "/new",
			CSRFTag:          template.JSStr(csrf.Token(r)),
		}

		err := tpl.ExecuteTemplate(w, "new_register.html", tplData)
		if err != nil {
			fmt.Println("AccountHandler: handleNewRegister: ", err)
			return
		}
	}
}

func (handler *AccountHandler) handleRegister() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error

		req := struct {
			Name            string `json:"name" validate:"required"`
			Email           string `json:"email" validate:"required,email"`
			PlainPassword   string `json:"password" validate:"required,min=8"`
			ConfirmPassword string `json:"confirm_password" validate:"required,min=8"`
		}{}

		switch contentType := r.Header.Get("Content-Type"); strings.ToLower(contentType) {
		case "application/json":
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, HttpError{
					Err: err.Error(),
				})
				return
			}
		case "application/x-www-form-urlencoded":
			req.Name = r.FormValue("name")
			req.Email = r.FormValue("email")
			req.PlainPassword = r.FormValue("password")
			req.ConfirmPassword = r.FormValue("confirm_password")

		default:
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: "invalid content type",
			})
			return
		}

		res := register.User{}
		lockKey := fmt.Sprintf("account_handler:register:email:%s", req.Email)
		err = handler.Locker.Lock(r.Context(), lockKey, func(ctx context.Context) error {
			res, err = handler.registerer.Register(r.Context(), handler.DB, register.RegisterRequest{
				PID:             req.Email,
				Name:            req.Name,
				Email:           req.Email,
				PlainPassword:   req.PlainPassword,
				ConfirmPassword: req.ConfirmPassword,
			})
			return err
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, HttpError{
				Err: err.Error(),
			})
			return
		}

		switch contentType := r.Header.Get("Content-Type"); strings.ToLower(contentType) {
		case "application/json":
			writeJSON(w, http.StatusOK, res)
		case "application/x-www-form-urlencoded":
			http.Redirect(w, r, handler.RegisterRedirectURL, http.StatusSeeOther)
		}
	}
}

func (handler *AccountHandler) handleVerifyRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pid := r.URL.Query().Get("pid")
		token := r.URL.Query().Get("token")

		res, err := handler.registerer.VerifyRegistration(r.Context(), handler.DB, register.VerifyRegistrationRequest{
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
