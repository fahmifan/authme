package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fahmifan/authme/backend/psql"
	"github.com/fahmifan/authme/integration/httpserver"
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

	base.waitServer()

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
		resp, err := suite.rr.R().Get("/healthz")
		if err != nil {
			continue
		}

		if resp.StatusCode() == http.StatusOK {
			continue
		}

		time.Sleep(1 * time.Second)
	}

	return errors.New("server not ready")
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

func (suite *IntegrationTestSuite) TestRegister() {
	suite.Run("register", func() {
		resp, err := suite.rr.R().
			SetBody(`{"email":"test@email.com","password":"test1234"}`).
			Post("/auth/register")

		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			fmt.Println("resp >>> ", resp.String())
			suite.FailNow(resp.String())
		}

		fmt.Println("resp >>> ", resp.String())
	})

	suite.Run("login", func() {
		_, err := suite.rr.R().
			SetBody(`{"email":"test@email.com","password":"test1234"}`).
			Post("/auth/register")

		suite.NoError(err)

		resp, err := suite.rr.R().
			SetBody(`{"email":"test@email.com", "password": "test1234"}`).
			Post("/auth")

		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			fmt.Println("resp >>> ", resp.String())
			suite.FailNow(resp.String())
		}

		fmt.Println("resp >>> ", resp.String())
	})
}
