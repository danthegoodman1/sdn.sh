package main

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore"
)

func openPostgres(ctx context.Context, url string, log zerolog.Logger) (store.Store, func(), error) {
	st, err := pgstore.Open(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	log.Info().Msg("connected to postgres; schema migrated")
	return st, st.Close, nil
}
