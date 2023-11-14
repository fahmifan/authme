//go:build integration_test

package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/httphandler"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/backend/sqlite"
	"github.com/fahmifan/authme/integration/httpserver"
	"github.com/fahmifan/authme/register"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type Map map[string]any

type TestUser struct {
	User          authme.User
	PlainPassword string
}

type DBKind string

const (
	DBKindPSQL   DBKind = "psql"
	DBKindSQLite DBKind = "sqlite"
)

type Base struct {
	dbkind DBKind
	suite.Suite
	rr     *resty.Client
	db     *sql.DB
	userRW authme.UserReadWriter
}

func TestIntegrationPSQL(t *testing.T) {
	base := NewPSQLBase(t)

	go func() {
		if err := httpserver.RunPSQLBackend(base.db); err != nil {
			require.NoError(t, err)
		}
	}()
	defer httpserver.Stop(context.TODO())

	err := base.waitServer()
	require.NoError(t, err)

	suite.Run(t, &AccountTestSuite{Base: base})
	suite.Run(t, &JWTTestSuite{Base: base})
	// suite.Run(t, &CookieTestSuite{Base: base})
}

func TestIntegrationSQLite(t *testing.T) {
	base := NewSQLiteBase(t)
	go func() {
		if err := httpserver.RunSQLiteBackend(base.db); err != nil {
			require.NoError(t, err)
		}
	}()
	defer httpserver.Stop(context.TODO())

	err := base.waitServer()
	require.NoError(t, err)

	suite.Run(t, &AccountTestSuite{Base: base})
	suite.Run(t, &JWTTestSuite{Base: base})
	// suite.Run(t, &CookieTestSuite{Base: base})
}

func NewPSQLBase(t *testing.T) *Base {
	base := &Base{
		dbkind: DBKindPSQL,
	}
	base.rr = resty.New()
	base.rr = base.rr.SetBaseURL("http://localhost:8080")

	var err error
	base.db, err = sql.Open("postgres", "postgres://root:root@localhost:5432/authme?sslmode=disable")
	require.NoError(t, err)

	base.userRW = psql.NewUserReadWriter()

	return base
}

func NewSQLiteBase(t *testing.T) *Base {
	base := &Base{
		dbkind: DBKindSQLite,
	}
	base.rr = resty.New()
	base.rr = base.rr.SetBaseURL("http://localhost:8080")

	var err error
	base.db, err = sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	base.userRW = sqlite.NewUserReadWriter()

	return base
}

func (suite *Base) SetupSubTest() {
	switch suite.dbkind {
	case DBKindPSQL:
		if err := psql.MigrateDown(suite.db); err != nil {
			fmt.Println("migrate down error: ", err)
		}

		err := psql.MigrateUp(suite.db)
		suite.NoError(err)

	case DBKindSQLite:
		if err := sqlite.MigrateDown(suite.db); err != nil {
			fmt.Println("migrate down error: ", err)
		}

		err := sqlite.MigrateUp(suite.db)
		suite.NoError(err)
	}
}

func (suite *Base) waitServer() error {
	waitInSecond := 10
	for i := 0; i < waitInSecond; i++ {
		// wait 1sec before check
		time.Sleep(1 * time.Second)

		resp, err := suite.rr.R().Get("/rest/healthz")
		if err != nil {
			continue
		}

		if resp.StatusCode() == http.StatusOK {
			return nil
		}
	}

	return errors.New("wait server timeout")
}

// Create new user and verify it.
// Copied from account_integration_test.go#TestRegisterAndVerify
func (suite *Base) prepareDefaultTestUser() TestUser {
	suite.T().Helper()

	name := "test user"
	email := "test@email.com"
	plainPassword := "test1234"

	return suite.preapreTestUser(name, email, plainPassword)
}

func (suite *Base) getCSRFToken() (token string, header string) {
	suite.T().Helper()

	resp, err := suite.rr.R().
		Get("/rest/auth/csrf")
	suite.NoError(err)

	if resp.StatusCode() != http.StatusOK {
		suite.FailNow(resp.String())
	}

	csrfRes := struct {
		CSRFToken string `json:"csrf_token"`
	}{}
	err = json.Unmarshal(resp.Body(), &csrfRes)
	suite.NoError(err)

	return csrfRes.CSRFToken, "x-csrf-token"
}

type CSRFTokenV2Response struct {
	CSRFToken  string
	CSRFHeader string
	CSRFCookie *http.Cookie
}

func (suite *Base) getCSRFTokenV2() CSRFTokenV2Response {
	suite.T().Helper()

	fmt.Println("DEBUG >>> getCSRFTokenV2")
	httpcl := http.Client{}
	httpres, err := httpcl.Get("http://localhost:8080/rest/auth/csrf")
	suite.NoError(err)

	csrfRes := struct {
		CSRFToken string `json:"csrf_token"`
	}{}
	err = json.NewDecoder(httpres.Body).Decode(&csrfRes)
	suite.NoError(err)

	setCookie := httpres.Header.Get("Set-Cookie")

	cookieStrs := strings.Split(setCookie, "=")
	cookieName := cookieStrs[0]
	cookieValue := strings.Split(cookieStrs[1], ";")[0]

	fmt.Println("DEBUG >>> getCSRFTokenV2 >>> cookieName >>> ", cookieName)
	fmt.Println("DEBUG >>> getCSRFTokenV2 >>> cookieValue >>> ", cookieValue)
	fmt.Println("DEBUG >>> getCSRFTokenV2 >>> csrfToken >>> ", csrfRes.CSRFToken)

	cookie := http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Secure:   true,
		Domain:   "localhost",
	}

	return CSRFTokenV2Response{
		CSRFToken:  csrfRes.CSRFToken,
		CSRFHeader: "X-Csrf-Token",
		CSRFCookie: &cookie,
	}
}

func (suite *Base) preapreTestUser(name, email, plainPassword string) TestUser {
	suite.T().Helper()

	csrfToken, csrfHeader := suite.getCSRFToken()

	resp, err := suite.rr.R().
		SetHeader(csrfHeader, csrfToken).
		SetBody(Map{
			"name":             name,
			"email":            email,
			"password":         plainPassword,
			"confirm_password": plainPassword,
		}).
		Post("/rest/auth/register")
	suite.NoError(err)
	if resp.StatusCode() != http.StatusOK {
		suite.FailNow(resp.String())
	}

	regUser := register.User{}
	err = json.Unmarshal(resp.Body(), &regUser)
	suite.NoError(err)

	// check verify token
	userRW := psql.NewUserReadWriter()
	user, err := userRW.FindByPID(context.Background(), suite.db, regUser.PID)
	suite.NoError(err)

	resp, err = suite.rr.R().
		SetQueryParams(map[string]string{
			"token": user.VerifyToken,
			"pid":   user.PID,
		}).
		Get(fmt.Sprintf("/rest/auth/verify"))
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode())

	return TestUser{
		User:          user,
		PlainPassword: plainPassword,
	}
}

func (suite *Base) prepareLoginCookies(testUser TestUser) []*http.Cookie {
	resp, err := suite.rr.R().
		SetBody(Map{
			"email":    testUser.User.Email,
			"password": testUser.PlainPassword,
		}).
		Post("/cookie/auth")
	suite.NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode())

	return resp.RawResponse.Cookies()
}

type JWTResponse struct {
	httphandler.JWTAuthResponse
	Cookies []*http.Cookie
}

func (jwtRes JWTResponse) AuthHeader() (header, value string) {
	return "Authorization", "Bearer " + jwtRes.AccessToken
}

func (suite *Base) prepareLoginJWT(testUser TestUser) JWTResponse {
	resp, err := suite.rr.R().
		SetBody(Map{
			"email":    testUser.User.Email,
			"password": testUser.PlainPassword,
		}).
		Post("/rest/auth")

	suite.NoError(err)
	if resp.StatusCode() != http.StatusOK {
		suite.FailNow(resp.String())
	}

	authRes := httphandler.JWTAuthResponse{}
	err = json.Unmarshal(resp.Body(), &authRes)
	suite.Require().NoError(err)

	return JWTResponse{
		JWTAuthResponse: authRes,
		Cookies:         resp.RawResponse.Cookies(),
	}
}
