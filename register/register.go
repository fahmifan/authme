package register

import (
	"context"
	"crypto/rand"
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

// Register is a use case for registering a new user.
type Register struct {
	verificationBaseURL string
	userRW              authme.UserReadWriter
	passwordHasher      authme.PasswordHasher
	mailer              authme.Mailer
	mailComposer        RegisterMailComposer
	guideGenerator      GUIDGenerator
	locker              authme.Locker
}

type NewRegisterArgs struct {
	VerificationBaseURL string
	UserRW              authme.UserReadWriter
	PasswordHasher      authme.PasswordHasher
	Mailer              authme.Mailer
	MailComposer        RegisterMailComposer
	GUIDGenerator       GUIDGenerator
	Locker              authme.Locker
}

func NewRegister(arg NewRegisterArgs) Register {
	return Register{
		userRW:              arg.UserRW,
		passwordHasher:      arg.PasswordHasher,
		verificationBaseURL: arg.VerificationBaseURL,
		mailer:              arg.Mailer,
		mailComposer:        arg.MailComposer,
		guideGenerator:      arg.GUIDGenerator,
		locker:              arg.Locker,
	}
}

type RegisterRequest struct {
	PID           string
	Email         string
	PlainPassword string
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

// Register registers a new user.
func (register Register) Register(ctx context.Context, req RegisterRequest) (User, error) {
	_, err := register.userRW.FindByPID(ctx, req.PID)
	if err != nil && !isErrNotFound(err) {
		return User{}, fmt.Errorf("read user: %w", err)
	}
	if !isErrNotFound(err) {
		return User{}, fmt.Errorf("user already exists")
	}

	user, err := authme.CreateUser(authme.CreateUserRequest{
		PasswordHasher: register.passwordHasher,
		GUID:           register.guideGenerator.Generate(),
		PID:            req.PID,
		Email:          req.Email,
		VerifyToken:    generateVerifyToken(),
		PlainPassword:  req.PlainPassword,
	})
	if err != nil {
		return User{}, fmt.Errorf("Register: CreateUser: %w", err)
	}

	user, err = register.userRW.Create(ctx, user)
	if err != nil {
		return User{}, fmt.Errorf("Register: save user: %w", err)
	}

	subject := register.mailComposer.ComposeSubject(user)
	mailBody, err := register.mailComposer.ComposeBody(user, register.verificationBaseURL)
	if err != nil {
		return User{}, fmt.Errorf("Register: compose email body: %w", err)
	}

	// TODO: might want to do pubsub/background to send email verification
	err = register.mailer.Send(ctx, authme.MailerSendArg{
		Subject: subject,
		From:    register.mailComposer.Sender(),
		To:      user.Email,
		Body:    mailBody,
	})
	if err != nil {
		return User{}, fmt.Errorf("Register: send email: %w", err)
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

func (register Register) VerifyRegistration(ctx context.Context, req VerifyRegistrationRequest) (res User, err error) {
	verifyLockKey := fmt.Sprintf("register:verify:%s", req.PID)
	err = register.locker.Lock(ctx, verifyLockKey, func(ctx context.Context) error {
		user, err := register.userRW.FindByPID(ctx, req.PID)
		if err != nil {
			return fmt.Errorf("VerifyRegistration: find user: %w", err)
		}

		user, err = user.VerifyStatus(req.VerifyToken)
		if err != nil {
			return fmt.Errorf("VerifyRegistration: verify status: %w", err)
		}

		user, err = register.userRW.Update(ctx, user)
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
	sender string
}

func NewDefaultMailComposer(sender string) DefaultMailComposer {
	return DefaultMailComposer{
		sender: sender,
	}
}

func (composer DefaultMailComposer) Sender() string {
	return composer.sender
}

func (composer DefaultMailComposer) ComposeSubject(user authme.User) string {
	return fmt.Sprintf("Confirm your registration %s", user.Name)
}

func (composer DefaultMailComposer) ComposeBody(user authme.User, baseURL string) (string, error) {
	hh := hermes.Hermes{}

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
