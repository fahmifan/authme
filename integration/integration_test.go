//go:build integration_test

package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/httphandler"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/integration/httpserver"
	"github.com/fahmifan/authme/register"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	_ "github.com/lib/pq"
)

type Map map[string]any

type TestUser struct {
	User          authme.User
	PlainPassword string
}

type Base struct {
	suite.Suite
	rr *resty.Client
	db *sql.DB
}

func TestIntegration(t *testing.T) {
	go func() {
		if err := httpserver.Run(); err != nil {
			require.NoError(t, err)
		}
	}()
	defer httpserver.Stop(context.TODO())

	base := NewBase(t)
	err := base.waitServer()
	require.NoError(t, err)

	suite.Run(t, &AccountTestSuite{Base: base})
	suite.Run(t, &JWTTestSuite{Base: base})
	suite.Run(t, &CookieTestSuite{Base: base})
}

func NewBase(t *testing.T) *Base {
	base := &Base{}
	base.rr = resty.New()
	base.rr = base.rr.SetBaseURL("http://localhost:8080")

	var err error
	base.db, err = sql.Open("postgres", "postgres://root:root@localhost:5432/authme?sslmode=disable")
	require.NoError(t, err)

	return base
}

func (suite *Base) SetupSubTest() {
	if err := psql.MigrateDown(suite.db); err != nil {
		fmt.Println("migrate down error: ", err)
	}

	err := psql.MigrateUp(suite.db)
	suite.NoError(err)
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
