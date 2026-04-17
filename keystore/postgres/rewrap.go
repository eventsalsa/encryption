package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/eventsalsa/encryption/cipher"
	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/systemkey"
)

const defaultRewrapBatchSize = 100

// RewrapSystemKeysOptions configures Store.RewrapSystemKeys.
type RewrapSystemKeysOptions struct {
	FromSystemKeyID string
	ToSystemKeyID   string
	BatchSize       int
	DryRun          bool
}

// RewrapSystemKeysResult summarizes a system-key rewrap run.
type RewrapSystemKeysResult struct {
	MatchedRows   int
	RewrappedRows int
	SkippedRows   int
	RemainingRows int
	Batches       int
}

type rewrapCandidate struct {
	Scope        string
	ScopeID      string
	KeyVersion   int
	EncryptedDEK []byte
}

func (o RewrapSystemKeysOptions) normalize() (RewrapSystemKeysOptions, error) {
	if o.FromSystemKeyID == "" {
		return RewrapSystemKeysOptions{}, fmt.Errorf("source system key ID is required")
	}
	if o.ToSystemKeyID == "" {
		return RewrapSystemKeysOptions{}, fmt.Errorf("target system key ID is required")
	}
	if o.FromSystemKeyID == o.ToSystemKeyID {
		return RewrapSystemKeysOptions{}, fmt.Errorf("source and target system key IDs must differ")
	}
	if o.BatchSize < 0 {
		return RewrapSystemKeysOptions{}, fmt.Errorf("batch size must be positive")
	}
	if o.BatchSize == 0 {
		o.BatchSize = defaultRewrapBatchSize
	}
	return o, nil
}

// RewrapSystemKeys re-encrypts stored DEKs from one system key to another in
// short PostgreSQL-managed batch transactions.
//
// This is an administrative operation for retiring old system keys. It updates
// only the stored encrypted DEK and system_key_id for matching rows; it does
// not create new DEK versions or touch application ciphertext.
func (s *Store) RewrapSystemKeys(ctx context.Context, keyring systemkey.Keyring, c cipher.Cipher, opts RewrapSystemKeysOptions) (RewrapSystemKeysResult, error) {
	if keyring == nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: keyring is nil")
	}
	if c == nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: cipher is nil")
	}

	opts, err := opts.normalize()
	if err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: %w", err)
	}

	sourceKey, err := keyring.Key(opts.FromSystemKeyID)
	if err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: get source system key: %w", err)
	}
	targetKey, err := keyring.Key(opts.ToSystemKeyID)
	if err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: get target system key: %w", err)
	}

	if opts.DryRun {
		remaining, err := s.countRowsBySystemKey(ctx, s.db, opts.FromSystemKeyID)
		if err != nil {
			return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: count dry-run rows: %w", err)
		}
		return RewrapSystemKeysResult{
			MatchedRows:   remaining,
			RemainingRows: remaining,
		}, nil
	}

	var result RewrapSystemKeysResult
	for {
		batch, err := s.rewrapSystemKeyBatch(ctx, sourceKey, targetKey, c, opts)
		if err != nil {
			return RewrapSystemKeysResult{}, err
		}
		if batch.MatchedRows == 0 {
			break
		}

		result.MatchedRows += batch.MatchedRows
		result.RewrappedRows += batch.RewrappedRows
		result.SkippedRows += batch.SkippedRows
		result.Batches += batch.Batches
	}

	remaining, err := s.countRowsBySystemKey(ctx, s.db, opts.FromSystemKeyID)
	if err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: count remaining rows: %w", err)
	}
	result.RemainingRows = remaining

	return result, nil
}

func (s *Store) rewrapSystemKeyBatch(ctx context.Context, sourceKey, targetKey []byte, c cipher.Cipher, opts RewrapSystemKeysOptions) (RewrapSystemKeysResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: begin batch tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	candidates, err := s.selectRowsForRewrap(ctx, tx, opts.FromSystemKeyID, opts.BatchSize)
	if err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: select batch: %w", err)
	}
	if len(candidates) == 0 {
		return RewrapSystemKeysResult{}, nil
	}

	result := RewrapSystemKeysResult{
		MatchedRows: len(candidates),
		Batches:     1,
	}
	for i, candidate := range candidates {
		rewrappedDEK, err := rewrapDEK(candidate.EncryptedDEK, sourceKey, targetKey, c)
		if err != nil {
			return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: rewrap batch row %d: %w", i, err)
		}

		updated, err := s.updateRewrappedRow(ctx, tx, candidate, rewrappedDEK, opts)
		if err != nil {
			return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: update batch row %d: %w", i, err)
		}
		if updated == 0 {
			result.SkippedRows++
			continue
		}
		result.RewrappedRows++
	}

	if err := tx.Commit(); err != nil {
		return RewrapSystemKeysResult{}, fmt.Errorf("postgres rewrap: commit batch tx: %w", err)
	}

	return result, nil
}

func rewrapDEK(encryptedDEK, sourceKey, targetKey []byte, c cipher.Cipher) ([]byte, error) {
	dek, err := c.Decrypt(sourceKey, encryptedDEK)
	if err != nil {
		return nil, err
	}
	defer encryption.ZeroBytes(dek)

	return c.Encrypt(targetKey, dek)
}

func (s *Store) selectRowsForRewrap(ctx context.Context, tx *sql.Tx, systemKeyID string, batchSize int) ([]rewrapCandidate, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key
		FROM %s
		WHERE system_key_id = $1
		ORDER BY scope, scope_id, key_version
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, s.fqtn())

	rows, err := tx.QueryContext(ctx, query, systemKeyID, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	candidates := make([]rewrapCandidate, 0, batchSize)
	for rows.Next() {
		var candidate rewrapCandidate
		if err := rows.Scan(&candidate.Scope, &candidate.ScopeID, &candidate.KeyVersion, &candidate.EncryptedDEK); err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (s *Store) updateRewrappedRow(ctx context.Context, tx *sql.Tx, candidate rewrapCandidate, encryptedDEK []byte, opts RewrapSystemKeysOptions) (int64, error) {
	query := fmt.Sprintf(`UPDATE %s
		SET encrypted_key = $1, system_key_id = $2
		WHERE scope = $3 AND scope_id = $4 AND key_version = $5 AND system_key_id = $6`, s.fqtn())

	result, err := tx.ExecContext(
		ctx,
		query,
		encryptedDEK,
		opts.ToSystemKeyID,
		candidate.Scope,
		candidate.ScopeID,
		candidate.KeyVersion,
		opts.FromSystemKeyID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) countRowsBySystemKey(ctx context.Context, conn queryable, systemKeyID string) (int, error) {
	query := fmt.Sprintf(`SELECT COUNT(*)
		FROM %s
		WHERE system_key_id = $1`, s.fqtn())

	var count int
	if err := conn.QueryRowContext(ctx, query, systemKeyID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
