//go:build integration_test

package integration_test

import (
	"encoding/json"
	"net/http"

	"github.com/fahmifan/authme/auth"
)

type JWTTestSuite struct {
	*Base
}

func (suite *JWTTestSuite) TestLogin() {
	suite.Run("login", func() {
		testUser := suite.prepareDefaultTestUser()

		// login
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

		loginResp := auth.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &loginResp)
		suite.NoError(err)

		suite.NotEmpty(loginResp.AccessToken)
		suite.NotEmpty(loginResp.RefreshToken)
		suite.NotZero(loginResp.ExpiredAt)
	})

	suite.Run("login multiple times", func() {
		testUser := suite.prepareDefaultTestUser()

		// login 1
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

		// login 2
		resp, err = suite.rr.R().
			SetBody(Map{
				"email":    testUser.User.Email,
				"password": testUser.PlainPassword,
			}).
			Post("/rest/auth")

		suite.NoError(err)
		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		loginResp := auth.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &loginResp)
		suite.NoError(err)

		suite.NotEmpty(loginResp.AccessToken)
		suite.NotEmpty(loginResp.RefreshToken)
		suite.NotZero(loginResp.ExpiredAt)
	})

	suite.Run("login with invalid credentials", func() {
		resp, err := suite.rr.R().
			SetBody(Map{
				"email":    "notfound@email.com",
				"password": "invalid",
			}).
			Post("/rest/auth")

		suite.NoError(err)
		if resp.StatusCode() != http.StatusNotFound {
			suite.FailNow(resp.String())
		}
	})
}

func (suite *JWTTestSuite) TestRefreshToken() {
	suite.Run("refreshing token", func() {
		testUser := suite.prepareDefaultTestUser()

		// login
		resp, err := suite.rr.R().
			SetBody(Map{
				"email":    testUser.User.Email,
				"password": testUser.PlainPassword,
			}).
			Post("/rest/auth")
		suite.NoError(err)

		loginResp := auth.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &loginResp)
		suite.NoError(err)

		// refreshing token
		resp, err = suite.rr.R().SetBody(Map{
			"refresh_token": loginResp.RefreshToken,
		}).Post("/rest/auth/refresh")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		refreshResp := auth.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &refreshResp)
		suite.NoError(err)

		suite.NotEmpty(refreshResp.AccessToken)
		suite.NotEmpty(refreshResp.RefreshToken)
		suite.NotZero(refreshResp.ExpiredAt)
	})
}
