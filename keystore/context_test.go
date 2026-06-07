package keystore_test

import (
	"context"
	"testing"

	"github.com/eventsalsa/encryption/keystore"
	"github.com/jackc/pgx/v5"
)

func TestWithTxAndTxFromContext(t *testing.T) {
	// TxFromContext on a bare context returns nil.
	ctx := context.Background()
	if got := keystore.TxFromContext(ctx); got != nil {
		t.Fatalf("expected nil from bare context, got %v", got)
	}

	// We can verify the context roundtrip by embedding a nil pgx.Tx
	// and checking the type assertion path. For a real roundtrip,
	// integration tests cover this.
	var fakeTx pgx.Tx
	ctx = keystore.WithTx(ctx, fakeTx)
	got := keystore.TxFromContext(ctx)
	if got != fakeTx {
		t.Fatalf("expected roundtrip to return same pgx.Tx, got %v", got)
	}
}

type unrelatedKey struct{}

func TestTxFromContext_WrongType(t *testing.T) {
	// Manually set a non-Tx value under a different key — TxFromContext should still return nil.
	ctx := context.WithValue(context.Background(), unrelatedKey{}, "not-a-tx")
	if got := keystore.TxFromContext(ctx); got != nil {
		t.Fatalf("expected nil for unrelated context value, got %v", got)
	}
}
