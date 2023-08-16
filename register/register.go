package register

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"

	"github.com/fahmifan/authme"
	"github.com/matcornic/hermes/v2"
)

type RegisterMailComposer interface {
	ComposeSubject(user authme.User) string
	ComposeBody(user authme.User, verificationBaseURL string) (string, error)
	Sender() string
}

type GUIDGenerator interface {
	Generate() string
}

type User struct {
	// GUID is global unique identifier can be UUID, Integer, etc.
	GUID string
	// PID is personal identifier can be email, username etc.
	PID    string
	Email  string
	Name   string
	Status authme.UserStatus
}

// Register is a use case for registering a new user.
type Register struct {
	verificationBaseURL string
	userRW              authme.UserReadWriter
	passwordHasher      authme.PasswordHasher
	mailer              authme.Mailer
	mailComposer        RegisterMailComposer
	guideGenerator      GUIDGenerator
}

type NewRegisterArgs struct {
	VerificationBaseURL string
	UserRW              authme.UserReadWriter
	PasswordHasher      authme.PasswordHasher
	Mailer              authme.Mailer
	MailComposer        RegisterMailComposer
	GUIDGenerator       GUIDGenerator
}

func NewRegister(arg NewRegisterArgs) Register {
	return Register{
		userRW:              arg.UserRW,
		passwordHasher:      arg.PasswordHasher,
		verificationBaseURL: arg.VerificationBaseURL,
		mailer:              arg.Mailer,
		mailComposer:        arg.MailComposer,
		guideGenerator:      arg.GUIDGenerator,
	}
}

type RegisterRequest struct {
	Name            string `json:"name" validate:"required"`
	PID             string `json:"pid" validate:"required,email"`
	Email           string `json:"email" validate:"required,email"`
	PlainPassword   string `json:"plain_password" validate:"required,min=8,max=32"`
	ConfirmPassword string `json:"confirm_password" validate:"required,min=8,max=32"`
}

// Register registers a new user.
func (register Register) Register(ctx context.Context, tx *sql.DB, req RegisterRequest) (User, error) {
	_, err := register.userRW.FindByPID(ctx, tx, req.PID)
	if err != nil && !isErrNotFound(err) {
		return User{}, fmt.Errorf("read user: %w", err)
	}
	if !isErrNotFound(err) {
		return User{}, fmt.Errorf("user already exists")
	}

	user, err := authme.CreateUser(authme.CreateUserRequest{
		PasswordHasher:  register.passwordHasher,
		GUID:            register.guideGenerator.Generate(),
		PID:             req.PID,
		Email:           req.Email,
		Name:            req.Name,
		VerifyToken:     generateVerifyToken(),
		PlainPassword:   req.PlainPassword,
		ConfirmPassword: req.ConfirmPassword,
	})
	if err != nil {
		return User{}, fmt.Errorf("Register: CreateUser: %w", err)
	}

	err = authme.Transaction(ctx, tx, func(ctx context.Context, tx authme.DBTX) error {
		user, err = register.userRW.Create(ctx, tx, user)
		if err != nil {
			return fmt.Errorf("Register: save user: %w", err)
		}

		subject := register.mailComposer.ComposeSubject(user)
		mailBody, err := register.mailComposer.ComposeBody(user, register.verificationBaseURL)
		if err != nil {
			return fmt.Errorf("Register: compose email body: %w", err)
		}

		err = register.mailer.Send(ctx, authme.MailerSendArg{
			Subject: subject,
			From:    register.mailComposer.Sender(),
			To:      user.Email,
			Body:    mailBody,
		})
		if err != nil {
			return fmt.Errorf("Register: send email: %w", err)
		}

		return nil
	})
	if err != nil {
		return User{}, err
	}

	res := User{
		GUID:   user.GUID,
		PID:    user.PID,
		Email:  user.Email,
		Name:   user.Name,
		Status: user.Status,
	}

	return res, nil
}

type VerifyRegistrationRequest struct {
	PID         string
	VerifyToken string
}

func (register Register) VerifyRegistration(ctx context.Context, tx *sql.DB, req VerifyRegistrationRequest) (res User, err error) {
	err = authme.Transaction(ctx, tx, func(ctx context.Context, tx authme.DBTX) error {
		user, err := register.userRW.FindByPID(ctx, tx, req.PID)
		if err != nil {
			return fmt.Errorf("VerifyRegistration: find user: %w", err)
		}

		user, err = user.VerifyStatus(req.VerifyToken)
		if err != nil {
			return fmt.Errorf("VerifyRegistration: verify status: %w", err)
		}

		user, err = register.userRW.Update(ctx, tx, user)
		if err != nil {
			return fmt.Errorf("VerifyRegistration: update user: %w", err)
		}

		res = User{
			GUID:   user.GUID,
			PID:    user.PID,
			Email:  user.Email,
			Name:   user.Name,
			Status: user.Status,
		}

		return nil
	})
	if err != nil {
		return User{}, err
	}

	return res, nil
}

func isErrNotFound(err error) bool {
	return errors.Is(err, authme.ErrNotFound)
}

const verifTokenLen = 32

func generateVerifyToken() string {
	b := make([]byte, verifTokenLen)
	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return base32.StdEncoding.EncodeToString(b)
}

type DefaultMailComposer struct {
	sender    string
	brandName string
}

func NewDefaultMailComposer(sender, brandName string) DefaultMailComposer {
	return DefaultMailComposer{
		sender:    sender,
		brandName: brandName,
	}
}

func (composer DefaultMailComposer) Sender() string {
	return composer.sender
}

func (composer DefaultMailComposer) ComposeSubject(user authme.User) string {
	return fmt.Sprintf("Confirm your registration %s", user.Name)
}

func (composer DefaultMailComposer) ComposeBody(user authme.User, baseURL string) (string, error) {
	hh := hermes.Hermes{
		Product: hermes.Product{
			Name: composer.brandName,
		},
	}

	mail := hermes.Email{
		Body: hermes.Body{
			Name: user.Name,
			Intros: []string{
				"You have received this email because you registered into our app",
			},
			Actions: []hermes.Action{
				{
					Instructions: "Click the button below to confirm your registration:",
					Button: hermes.Button{
						Color: "#DC4D2F",
						Text:  "Confirm your registration",
						Link:  fmt.Sprintf("%s?token=%s", baseURL, user.VerifyToken),
					},
				},
			},
			Outros: []string{
				"If you did not register to our app, you can safely ignore it.",
			},
			Signature: "Thanks",
		},
	}

	return hh.GenerateHTML(mail)
}
