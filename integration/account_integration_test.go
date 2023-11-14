//go:build integration_test

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fahmifan/authme/register"
)

type AccountTestSuite struct {
	*Base
}

func (suite *AccountTestSuite) TestRegisterAndVerify() {
	suite.Run("register & verify", func() {
		csrfToken, csrfHeader := suite.getCSRFToken()

		resp, err := suite.rr.R().
			SetHeader(csrfHeader, csrfToken).
			SetBody(Map{
				"name":             "test user",
				"email":            "test@email.com",
				"password":         "test1234",
				"confirm_password": "test1234",
			}).
			Post("/rest/auth/register")

		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		registerResp := register.User{}
		err = json.Unmarshal(resp.Body(), &registerResp)
		suite.NoError(err)
		suite.Equal("test user", registerResp.Name)

		// check verify token
		user, err := suite.userRW.FindByPID(context.Background(), suite.db, registerResp.PID)
		suite.NoError(err)

		resp, err = suite.rr.R().
			SetQueryParams(map[string]string{
				"token": user.VerifyToken,
				"pid":   user.PID,
			}).
			Get(fmt.Sprintf("/rest/auth/verify"))
		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}
	})
}
