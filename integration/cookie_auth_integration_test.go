//go:build integration_test

package integration_test

import (
	"fmt"
	"math/rand"
	"net/http"

	"github.com/fahmifan/authme/backend/httphandler"
	"golang.org/x/sync/errgroup"
)

type CookieTestSuite struct {
	*Base
}

func (suite *CookieTestSuite) TestLogin() {
	suite.Run("login", func() {
		testUser := suite.prepareDefaultTestUser()
		csrfToken, csrfHeader := suite.getCSRFToken()

		// login
		resp, err := suite.rr.R().
			SetHeader(csrfHeader, csrfToken).
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

	suite.Run("login multiple times", func() {
		suite.T().Skip()

		testUser := suite.prepareDefaultTestUser()

		// login 1
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

		// login 2
		resp, err = suite.rr.R().
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

	suite.Run("login with invalid credentials", func() {
		suite.T().Skip()

		resp, err := suite.rr.R().
			SetBody(Map{
				"email":    "notfound@email.com",
				"password": "invalid",
			}).
			Post("/cookie/auth")

		suite.NoError(err)
		if resp.StatusCode() != http.StatusNotFound {
			suite.FailNow(resp.String())
		}
	})
}

func (suite *CookieTestSuite) TestLoginConcurrent() {
	suite.Run("login concurrent", func() {
		nusers := 10
		nitter := 100
		testUserChan := make(chan TestUser, nusers)

		eg := errgroup.Group{}
		insertEg := errgroup.Group{}
		insertEg.SetLimit(20)

		password := "test1234"
		for i := 0; i < nusers; i++ {
			email := fmt.Sprintf("test%d@email.com", i)
			name := fmt.Sprintf("test%d", i)

			insertEg.Go(func() error {
				testUserChan <- suite.preapreTestUser(name, email, password)
				return nil
			})
		}

		err := insertEg.Wait()
		close(testUserChan)
		suite.NoError(err)

		var testUsers []TestUser
		for testUser := range testUserChan {
			testUsers = append(testUsers, testUser)
		}

		for i := 0; i < nitter; i++ {
			idx := rand.Intn(nusers - 1)
			testUser := testUsers[idx]

			eg.Go(func() error {
				resp, err := suite.rr.R().
					SetBody(Map{
						"email":    testUser.User.Email,
						"password": testUser.PlainPassword,
					}).
					Post("/cookie/auth")
				suite.NoError(err)
				if resp.StatusCode() != http.StatusOK {
					return fmt.Errorf("status code is not 200 %d: resp: %s", resp.StatusCode(), resp.String())
				}

				return nil
			})
		}

		err = eg.Wait()
		suite.NoError(err)
	})
}

func (suite *CookieTestSuite) TestPrivateRoute() {
	suite.Run("failed unauthenticated private route", func() {
		resp, err := suite.rr.R().
			Get("/private-cookie")
		suite.NoError(err)

		if resp.StatusCode() != http.StatusUnauthorized {
			suite.FailNow(resp.String())
		}
	})

	suite.Run("private route", func() {
		testUser := suite.prepareDefaultTestUser()
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
