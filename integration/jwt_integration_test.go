//go:build integration_test

package integration_test

import (
	"encoding/json"
	"net/http"

	"github.com/fahmifan/authme/backend/httphandler"
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

		loginResp := httphandler.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &loginResp)
		suite.NoError(err)

		suite.NotEmpty(loginResp.AccessToken)
		suite.NotZero(loginResp.ExpiredAt)

		cookie := resp.Cookies()[0]
		suite.Require().NotEmpty(cookie)
		suite.Require().Equal(httphandler.CookieRefreshToken, cookie.Name)
		suite.Require().Equal(true, cookie.Secure)
		suite.Require().NotEmpty(cookie.Value)
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

		loginResp := httphandler.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &loginResp)
		suite.NoError(err)

		suite.NotEmpty(loginResp.AccessToken)
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
	suite.Run("failed refreshing token, no cookie", func() {
		resp, err := suite.rr.R().
			Post("/rest/auth/refresh")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusBadRequest {
			suite.FailNow(resp.String())
		}
	})

	suite.Run("refreshing token", func() {
		testUser := suite.prepareDefaultTestUser()
		jwtRes := suite.prepareLoginJWT(testUser)

		// refreshing token
		resp, err := suite.rr.R().
			SetCookies(jwtRes.Cookies).
			Post("/rest/auth/refresh")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		refreshResp := httphandler.JWTAuthResponse{}
		err = json.Unmarshal(resp.Body(), &refreshResp)
		suite.NoError(err)

		suite.NotEmpty(refreshResp.AccessToken)
		suite.NotZero(refreshResp.ExpiredAt)

		cookie := resp.Cookies()[0]
		suite.Require().NotEmpty(cookie)
		suite.Require().Equal(httphandler.CookieRefreshToken, cookie.Name)
		suite.Require().Equal(true, cookie.Secure)
		suite.Require().NotEmpty(cookie.Value)
	})
}

func (suite *JWTTestSuite) TestPrivateRoute() {
	suite.Run("failed unauthenticated private route", func() {
		resp, err := suite.rr.R().
			SetHeader("Authorization", "Bearer invalid.token").
			Get("/private-jwt")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusUnauthorized {
			suite.FailNow(resp.String())
		}
	})

	suite.Run("ok private route", func() {
		testUser := suite.prepareDefaultTestUser()
		jwtAuth := suite.prepareLoginJWT(testUser)

		resp, err := suite.rr.R().
			SetHeader(jwtAuth.AuthHeader()).
			Get("/private-jwt")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		suite.Equal("ok", resp.String())
	})
}
