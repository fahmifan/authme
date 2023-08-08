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
	tx sqlcs.DBTX
}

func NewSessionReadWriter(tx sqlcs.DBTX) SessionReadWriter {
	return SessionReadWriter{tx: tx}
}

func (psql SessionReadWriter) FindByToken(ctx context.Context, token string) (auth.Session, error) {
	query := sqlcs.New(psql.tx)

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

	sess := auth.Session{
		Token:          xsess.Token,
		TokenExpiredAt: xsess.TokenExpiredAt,
		User: authme.User{
			GUID:         xuser.ID.String(),
			PID:          xuser.Email,
			PasswordHash: xuser.PasswordHash,
		},
	}

	return sess, nil
}

func (psql SessionReadWriter) Create(ctx context.Context, sess auth.Session) (auth.Session, error) {
	query := sqlcs.New(psql.tx)

	guid, err := uuid.Parse(sess.User.GUID)
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: Create: parse guid: %w", err)
	}

	_, err = query.InsertSession(ctx, sqlcs.InsertSessionParams{
		Token:          sess.Token,
		TokenExpiredAt: sess.TokenExpiredAt,
		UserID:         guid,
	})
	if err != nil {
		return auth.Session{}, fmt.Errorf("SessionReadWriter: InsertSession: %w", err)
	}

	return sess, nil
}

func (psql SessionReadWriter) Update(ctx context.Context, sess auth.Session) (auth.Session, error) {
	query := sqlcs.New(psql.tx)

	guid, err := uuid.Parse(sess.User.GUID)
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
