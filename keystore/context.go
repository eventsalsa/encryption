package keystore

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type txKey struct{}

// WithTx returns a child context carrying the given transaction.
// The PostgreSQL KeyStore implementation will use this transaction
// for all operations (reads and writes) instead of the connection pool.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TxFromContext extracts the transaction set by WithTx, or returns nil.
func TxFromContext(ctx context.Context) pgx.Tx {
	tx, _ := ctx.Value(txKey{}).(pgx.Tx)
	return tx
}
