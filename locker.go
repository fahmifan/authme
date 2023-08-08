package authme

import (
	"context"
	"fmt"

	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidislock"
)

type Locker interface {
	Lock(ctx context.Context, key string, fn func(ctx context.Context) error) error
}

type RedisLock struct {
	locker rueidislock.Locker
}

func NewRedisLock(host string) (RedisLock, error) {
	locker, err := rueidislock.NewLocker(rueidislock.LockerOption{
		ClientOption: rueidis.ClientOption{InitAddress: []string{host}},
		KeyMajority:  1,
	})
	if err != nil {
		return RedisLock{}, err
	}

	return RedisLock{locker: locker}, nil
}

func (tx RedisLock) Lock(ctx context.Context, key string, fn func(ctx context.Context) error) error {
	ctx, cancel, err := tx.locker.WithContext(ctx, key)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer cancel()

	if fn(ctx); err != nil {
		return err
	}

	return nil
}
