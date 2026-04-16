package keystore

import (
	"context"
	"database/sql"
)

type txKey struct{}

// WithTx returns a child context carrying the given transaction.
// The PostgreSQL KeyStore implementation will use this transaction
// for all operations (reads and writes) instead of the connection pool.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TxFromContext extracts the transaction set by WithTx, or returns nil.
func TxFromContext(ctx context.Context) *sql.Tx {
	tx, _ := ctx.Value(txKey{}).(*sql.Tx)
	return tx
}
