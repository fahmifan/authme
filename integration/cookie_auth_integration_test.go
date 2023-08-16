//go:build integration_test

package integration_test

import (
	"net/http"

	"github.com/fahmifan/authme/backend/httphandler"
)

type CookieTestSuite struct {
	*Base
}

func (suite *CookieTestSuite) TestLogin() {
	suite.Run("login", func() {
		testUser := suite.prepareTestUser()

		// login
		resp, err := suite.rr.R().
			SetBody(Map{
				"email":    testUser.User.Email,
				"password": testUser.PlainPassword,
			}).
			Post("/cookie/auth")

		suite.NoError(err)
		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		suite.Equal(httphandler.SessionStoreKey, resp.RawResponse.Cookies()[0].Name)
		suite.NotEmpty(resp.RawResponse.Cookies()[0].Value)
		suite.Equal("/", resp.RawResponse.Cookies()[0].Path)
		suite.Equal("localhost", resp.RawResponse.Cookies()[0].Domain)
	})
}

func (suite *CookieTestSuite) TestPrivateRoute() {
	suite.Run("private route", func() {
		testUser := suite.prepareTestUser()
		cookies := suite.prepareLoginCookies(testUser)

		resp, err := suite.rr.R().
			SetCookies(cookies).
			Get("/private-cookie")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusOK {
			suite.FailNow(resp.String())
		}

		suite.Equal("ok", resp.String())
	})
}
