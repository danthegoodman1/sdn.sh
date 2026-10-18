package main

import (
	"context"
	"errors"

	"github.com/rs/zerolog"

	"sdn.sh/internal/store"
)

func openPostgres(ctx context.Context, url string, log zerolog.Logger) (store.Store, func(), error) {
	return nil, nil, errors.New("postgres store not built yet")
}
