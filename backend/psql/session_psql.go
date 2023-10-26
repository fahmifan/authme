package psql

import (
	"context"
	"fmt"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/fahmifan/authme/backend/psql/sqlcs"
	"github.com/google/uuid"
)

var _ auth.SessionReader = SessionReadWriter{}
var _ auth.SessionWriter = SessionReadWriter{}

type SessionReadWriter struct {
}

func NewSessionReadWriter() SessionReadWriter {
	return SessionReadWriter{}
}

func (psql SessionReadWriter) FindByToken(ctx context.Context, tx authme.DBTX, token string) (auth.Session, error) {
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
		GUID:   xsess.ID.String(),
		PID:    xsess.Email,
		Email:  xsess.Email,
		Name:   xsess.Name,
		Status: authme.UserStatus(xsess.Status),
	}
}

func sessionFromSQL(xsess sqlcs.UserSession, xuser sqlcs.User) auth.Session {
	return auth.Session{
		GUID:           xsess.ID.String(),
		Token:          xsess.Token,
		TokenExpiredAt: xsess.TokenExpiredAt,
		User:           userSessionFromSQL(xuser),
	}
}

func (psql SessionReadWriter) Create(ctx context.Context, tx authme.DBTX, sess auth.Session) (auth.Session, error) {
	query := sqlcs.New(tx)

	id, err := uuid.Parse(sess.GUID)
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: Create: parse guid: %w", err)
	}

	userID, err := uuid.Parse(sess.User.GUID)
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: Create: parse guid: %w", err)
	}

	_, err = query.InsertSession(ctx, sqlcs.InsertSessionParams{
		ID:             id,
		UserID:         userID,
		Token:          sess.Token,
		TokenExpiredAt: sess.TokenExpiredAt,
	})
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: InsertSession: %w", err)
	}

	return sess, nil
}

func (psql SessionReadWriter) Update(ctx context.Context, tx authme.DBTX, sess auth.Session) (auth.Session, error) {
	query := sqlcs.New(tx)

	guid, err := uuid.Parse(sess.GUID)
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: Update: parse guid: %w", err)
	}

	_, err = query.UpdateSession(ctx, sqlcs.UpdateSessionParams{
		ID:             guid,
		Token:          sess.Token,
		TokenExpiredAt: sess.TokenExpiredAt,
	})
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: UpdateSession: %w", err)
	}

	return sess, nil
}
