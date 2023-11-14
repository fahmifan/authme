package sqlite

import (
	"context"
	"fmt"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/sqlite/sqlcs"
)

var _ auth.SessionReader = SessionReadWriter{}
var _ auth.SessionWriter = SessionReadWriter{}

type SessionReadWriter struct {
}

func NewSessionReadWriter() SessionReadWriter {
	return SessionReadWriter{}
}

func (rw SessionReadWriter) FindByToken(ctx context.Context, tx authme.DBTX, token string) (auth.Session, error) {
	query := sqlcs.New(tx)

	xsess, err := query.FindSessionByToken(ctx, token)
	if err != nil {
		if isNotFoundErr(err) {
			return auth.Session{}, auth.ErrorSessionNotFound
		}

		return auth.Session{}, fmt.Errorf("PSQL: FindSessionByToken: %w", err)
	}

	xuser, err := query.FindUserByID(ctx, xsess.UserID)
	if err != nil {
		if isNotFoundErr(err) {
			return auth.Session{}, auth.ErrorSessionNotFound
		}
	}

	sess := sessionFromSQL(xsess, xuser)

	return sess, nil
}

func userSessionFromSQL(xsess sqlcs.User) auth.UserSession {
	return auth.UserSession{
		GUID:      xsess.ID,
		PID:       xsess.Email,
		Email:     xsess.Email,
		Name:      xsess.Name,
		Status:    authme.UserStatus(xsess.Status),
		CreatedAt: xsess.CreatedAt,
		UpdatedAt: xsess.UpdatedAt,
	}
}

func sessionFromSQL(xsess sqlcs.UserSession, xuser sqlcs.User) auth.Session {
	return auth.Session{
		GUID:           xsess.ID,
		Token:          xsess.Token,
		TokenExpiredAt: xsess.TokenExpiredAt,
		User:           userSessionFromSQL(xuser),
	}
}

func (rw SessionReadWriter) Create(ctx context.Context, tx authme.DBTX, sess auth.Session) (auth.Session, error) {
	query := sqlcs.New(tx)

	_, err := query.InsertSession(ctx, sqlcs.InsertSessionParams{
		ID:             sess.GUID,
		UserID:         sess.User.GUID,
		Token:          sess.Token,
		TokenExpiredAt: sess.TokenExpiredAt,
		CreatedAt:      sess.User.CreatedAt,
		UpdatedAt:      sess.User.UpdatedAt,
	})
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: InsertSession: %w", err)
	}

	return sess, nil
}

func (rw SessionReadWriter) Update(ctx context.Context, tx authme.DBTX, sess auth.Session) (auth.Session, error) {
	query := sqlcs.New(tx)

	_, err := query.UpdateSession(ctx, sqlcs.UpdateSessionParams{
		ID:             sess.GUID,
		Token:          sess.Token,
		TokenExpiredAt: sess.TokenExpiredAt,
	})
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: UpdateSession: %w", err)
	}

	return sess, nil
}
