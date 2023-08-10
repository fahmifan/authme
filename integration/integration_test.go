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

	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/integration/httpserver"
	"github.com/fahmifan/authme/register"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	_ "github.com/lib/pq"
)

func TestIntegration(t *testing.T) {
	base := NewBase(t)

	go func() {
		if err := httpserver.Run(); err != nil {
			fmt.Println("httpserver run error: ", err)
		}
	}()
	defer httpserver.Stop(context.TODO())

	err := base.waitServer()
	require.NoError(t, err)

	integrationTestSuite := IntegrationTestSuite{Base: base}
	suite.Run(t, &integrationTestSuite)
}

type Base struct {
	suite.Suite
	rr *resty.Client
	db *sql.DB
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

func (suite *Base) waitServer() error {
	for i := 0; i < 10; i++ {
		// wait before check
		time.Sleep(1 * time.Second)

		resp, err := suite.rr.R().Get("/healthz")
		if err != nil {
			continue
		}

		if resp.StatusCode() == http.StatusOK {
			return nil
		}
	}

	return errors.New("wait server timeout")
}

func (suite *Base) SetupSubTest() {
	if err := psql.MigrateDown(suite.db); err != nil {
		fmt.Println("migrate down error: ", err)
	}

	err := psql.MigrateUp(suite.db)
	suite.NoError(err)
}

type IntegrationTestSuite struct {
	*Base
}

type Map map[string]any

func (suite *IntegrationTestSuite) TestRegister() {
	suite.Run("register & verify", func() {
		resp, err := suite.rr.R().
			SetBody(Map{
				"name":            "test user",
				"email":           "test@email.com",
				"password":        "test1234",
				"confirmPassword": "test1234",
			}).
			Post("/auth/register")

		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			fmt.Println("resp >>> ", resp.String())
			suite.FailNow(resp.String())
		}

		registerResp := register.User{}
		err = json.Unmarshal(resp.Body(), &registerResp)
		suite.NoError(err)

		suite.Equal("test user", registerResp.Name)

		// check verify token
		userRW := psql.NewUserReadWriter(suite.db)
		user, err := userRW.FindByPID(context.Background(), registerResp.PID)
		suite.NoError(err)

		resp, err = suite.rr.R().
			SetQueryParams(map[string]string{
				"token": user.VerifyToken,
				"pid":   user.PID,
			}).
			Get(fmt.Sprintf("/auth/verify"))
		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			fmt.Println("resp >>> ", resp.String())
			suite.FailNow(resp.String())
		}
	})

	suite.Run("login", func() {
		// register
		_, err := suite.rr.R().
			SetBody(Map{
				"name":            "test user",
				"email":           "test@email.com",
				"password":        "test1234",
				"confirmPassword": "test1234",
			}).
			Post("/auth/register")

		suite.NoError(err)

		// login
		resp, err := suite.rr.R().
			SetBody(Map{
				"email":    "test@email.com",
				"password": "test1234",
			}).
			Post("/auth")

		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			fmt.Println("resp >>> ", resp.String())
			suite.FailNow(resp.String())
		}

		loginResp := auth.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &loginResp)
		suite.NoError(err)

		suite.NotEmpty(loginResp.AccessToken)
		suite.NotEmpty(loginResp.RefreshToken)
		suite.NotZero(loginResp.ExpiredAt)
	})
}
