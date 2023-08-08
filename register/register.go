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
}

type GUIDGenerator interface {
	Generate() string
}

// Register is a use case for registering a new user.
type Register struct {
	verificationBaseURL string
	userRW              authme.UserReadWriter
	hasher              authme.PasswordHasher
	mailer              authme.Mailer
	mailComposer        RegisterMailComposer
	guideGenerator      GUIDGenerator
	locker              authme.Locker
}

func NewRegister(
	userRW authme.UserReadWriter,
	hasher authme.PasswordHasher,
) Register {
	return Register{
		userRW: userRW,
		hasher: hasher,
	}
}

type RegisterRequest struct {
	PID           string
	Email         string
	PlainPassword string
}

// Register registers a new user.
func (register Register) Register(ctx context.Context, req RegisterRequest) (authme.User, error) {
	_, err := register.userRW.FindByPID(ctx, req.PID)
	if err != nil && !isErrNotFound(err) {
		return authme.User{}, fmt.Errorf("read user: %w", err)
	}
	if !isErrNotFound(err) {
		return authme.User{}, fmt.Errorf("user already exists")
	}

	user, err := authme.CreateUser(authme.CreateUserRequest{
		PasswordHasher: register.hasher,
		GUID:           register.guideGenerator.Generate(),
		PID:            req.PID,
		Email:          req.Email,
		VerifyToken:    generateVerifyToken(),
		PlainPassword:  req.PlainPassword,
	})
	if err != nil {
		return authme.User{}, fmt.Errorf("Register: CreateUser: %w", err)
	}

	user, err = register.userRW.Create(ctx, user)
	if err != nil {
		return authme.User{}, fmt.Errorf("Register: save user: %w", err)
	}

	subject := register.mailComposer.ComposeSubject(user)
	mailBody, err := register.mailComposer.ComposeBody(user, register.verificationBaseURL)
	if err != nil {
		return authme.User{}, fmt.Errorf("Register: compose email body: %w", err)
	}

	// TODO: might want to do pubsub/background to send email verification
	err = register.mailer.Send(ctx, user.Email, subject, mailBody)
	if err != nil {
		return authme.User{}, fmt.Errorf("Register: send email: %w", err)
	}

	return user, nil
}

type VerifyRegistrationRequest struct {
	PID         string
	VerifyToken string
}

func (register Register) VerifyRegistration(ctx context.Context, req VerifyRegistrationRequest) (user authme.User, err error) {
	verifyLockKey := fmt.Sprintf("register:verify:%s", req.PID)
	err = register.locker.Lock(ctx, verifyLockKey, func(ctx context.Context) error {
		user, err = register.userRW.FindByPID(ctx, req.PID)
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

		return nil
	})
	if err != nil {
		return authme.User{}, err
	}

	return user, nil
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
	Sender string
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
