package postgres

import (
	"context"
	"fmt"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultRewrapBatchSize = 100

// RewrapKeysOptions configures RewrapKeys.
type RewrapKeysOptions struct {
	FromKEKID string
	ToKEKID   string
	BatchSize int
	DryRun    bool
}

// RewrapKeysResult summarizes a KEK rewrap run.
type RewrapKeysResult struct {
	MatchedRows   int
	RewrappedRows int
	SkippedRows   int
	RemainingRows int
	Batches       int
}

func (o RewrapKeysOptions) normalize() (RewrapKeysOptions, error) {
	if o.FromKEKID == "" {
		return RewrapKeysOptions{}, fmt.Errorf("source KEK ID is required: %w", encryption.ErrInvalidConfig)
	}
	if o.ToKEKID == "" {
		return RewrapKeysOptions{}, fmt.Errorf("target KEK ID is required: %w", encryption.ErrInvalidConfig)
	}
	if o.FromKEKID == o.ToKEKID {
		return RewrapKeysOptions{}, fmt.Errorf("source and target KEK IDs must differ: %w", encryption.ErrInvalidConfig)
	}
	if o.BatchSize < 0 {
		return RewrapKeysOptions{}, fmt.Errorf("batch size must be positive: %w", encryption.ErrInvalidConfig)
	}
	if o.BatchSize == 0 {
		o.BatchSize = defaultRewrapBatchSize
	}
	return o, nil
}

// RewrapKeys re-encrypts stored DEKs from one KEK to another in short
// PostgreSQL-managed batch transactions.
//
// This is an administrative operation for retiring old KEKs or migrating across
// KMS providers. It updates only the stored encrypted_dek and kek_id for
// matching rows while preserving and verifying each row's (scope, scope_id, key_version) AAD.
func RewrapKeys(ctx context.Context, pool *pgxpool.Pool, cfg Config, env *envelope.Envelope, opts RewrapKeysOptions) (RewrapKeysResult, error) {
	if pool == nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: pool is nil: %w", encryption.ErrInvalidConfig)
	}
	if env == nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: envelope is nil: %w", encryption.ErrInvalidConfig)
	}

	cfg = ApplyDefaults(cfg)
	opts, err := opts.normalize()
	if err != nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: %w", err)
	}

	fqtn := fmt.Sprintf("%s.%s", cfg.Schema, cfg.Table)

	if opts.DryRun {
		remaining, err := countRowsByKEK(ctx, pool, fqtn, opts.FromKEKID)
		if err != nil {
			return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: count dry-run rows: %w", err)
		}
		return RewrapKeysResult{
			MatchedRows:   remaining,
			RemainingRows: remaining,
		}, nil
	}

	var result RewrapKeysResult
	for {
		batch, err := rewrapKeyBatch(ctx, pool, fqtn, env, opts)
		if err != nil {
			return RewrapKeysResult{}, err
		}
		if batch.MatchedRows == 0 {
			break
		}

		result.MatchedRows += batch.MatchedRows
		result.RewrappedRows += batch.RewrappedRows
		result.SkippedRows += batch.SkippedRows
		result.Batches += batch.Batches
	}

	remaining, err := countRowsByKEK(ctx, pool, fqtn, opts.FromKEKID)
	if err != nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: count remaining rows: %w", err)
	}
	result.RemainingRows = remaining

	return result, nil
}

func rewrapKeyBatch(ctx context.Context, pool *pgxpool.Pool, fqtn string, env *envelope.Envelope, opts RewrapKeysOptions) (RewrapKeysResult, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: begin batch tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Best-effort cleanup; commit path handles the success case explicitly.

	candidates, err := selectRowsForRewrap(ctx, tx, fqtn, opts.FromKEKID, opts.BatchSize)
	if err != nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: select batch: %w", err)
	}
	if len(candidates) == 0 {
		return RewrapKeysResult{}, nil
	}

	result := RewrapKeysResult{
		MatchedRows: len(candidates),
		Batches:     1,
	}
	for i := range candidates {
		candidate := &candidates[i]
		rewrappedDEK, err := env.RewrapDEK(ctx, candidate, opts.ToKEKID)
		if err != nil {
			return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: rewrap batch row %d: %w", i, err)
		}

		updated, err := updateRewrappedRow(ctx, tx, fqtn, candidate, rewrappedDEK, opts)
		if err != nil {
			return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: update batch row %d: %w", i, err)
		}
		if updated == 0 {
			result.SkippedRows++
			continue
		}
		result.RewrappedRows++
	}

	if err := tx.Commit(ctx); err != nil {
		return RewrapKeysResult{}, fmt.Errorf("postgres rewrap: commit batch tx: %w", err)
	}

	return result, nil
}

func selectRowsForRewrap(ctx context.Context, tx pgx.Tx, fqtn, kekID string, batchSize int) ([]encryption.EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_dek, kek_id
		FROM %s
		WHERE kek_id = $1
		ORDER BY scope, scope_id, key_version
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, fqtn) //#nosec G201 -- fqtn is derived from trusted postgres.Config schema/table settings, not user input.

	rows, err := tx.Query(ctx, query, kekID, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	candidates := make([]encryption.EncryptedKey, 0, batchSize)
	for rows.Next() {
		var candidate encryption.EncryptedKey
		if err := rows.Scan(&candidate.Scope, &candidate.ScopeID, &candidate.KeyVersion, &candidate.EncryptedDEK, &candidate.KEKID); err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func updateRewrappedRow(ctx context.Context, tx pgx.Tx, fqtn string, candidate *encryption.EncryptedKey, encryptedDEK []byte, opts RewrapKeysOptions) (int64, error) {
	query := fmt.Sprintf(`UPDATE %s
		SET encrypted_dek = $1, kek_id = $2
		WHERE scope = $3 AND scope_id = $4 AND key_version = $5 AND kek_id = $6`, fqtn) //#nosec G201 -- fqtn is derived from trusted postgres.Config schema/table settings, not user input.

	cmdTag, err := tx.Exec(
		ctx,
		query,
		encryptedDEK,
		opts.ToKEKID,
		candidate.Scope,
		candidate.ScopeID,
		candidate.KeyVersion,
		opts.FromKEKID,
	)
	if err != nil {
		return 0, err
	}
	return cmdTag.RowsAffected(), nil
}

func countRowsByKEK(ctx context.Context, conn pgxConn, fqtn, kekID string) (int, error) {
	query := fmt.Sprintf(`SELECT COUNT(*)
		FROM %s
		WHERE kek_id = $1`, fqtn) //#nosec G201 -- fqtn is derived from trusted postgres.Config schema/table settings, not user input.

	var count int
	if err := conn.QueryRow(ctx, query, kekID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
