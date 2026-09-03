package db

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const presharedKeyBackfillBatchSize = 100

type PresharedKeyBackfillReport struct {
	Peers          int
	PeerOperations int
	MeshMembers    int
}

type presharedKeyBackfillTarget struct {
	table string
	scope dataencryption.Scope
}

var presharedKeyBackfillTargets = []presharedKeyBackfillTarget{
	{table: "peers", scope: dataencryption.PeerPresharedKey},
	{table: "peer_operations", scope: dataencryption.PeerOperationPresharedKey},
	{table: "mesh_members", scope: dataencryption.MeshMemberPresharedKey},
}

// BackfillPresharedKeys encrypts legacy plaintext in bounded transactions. A
// row is cleared only after an authenticated round trip succeeds. The query is
// idempotent and SKIP LOCKED permits safe restart or concurrent workers.
func BackfillPresharedKeys(ctx context.Context, pool *pgxpool.Pool, cipher *dataencryption.Cipher) (PresharedKeyBackfillReport, error) {
	if cipher == nil {
		return PresharedKeyBackfillReport{}, dataencryption.ErrUnavailable
	}
	report := PresharedKeyBackfillReport{}
	for _, target := range presharedKeyBackfillTargets {
		count, err := backfillPresharedKeyTable(ctx, pool, cipher, target)
		if err != nil {
			return report, err
		}
		switch target.scope {
		case dataencryption.PeerPresharedKey:
			report.Peers = count
		case dataencryption.PeerOperationPresharedKey:
			report.PeerOperations = count
		case dataencryption.MeshMemberPresharedKey:
			report.MeshMembers = count
		}
	}
	return report, nil
}

func backfillPresharedKeyTable(ctx context.Context, pool *pgxpool.Pool, cipher *dataencryption.Cipher, target presharedKeyBackfillTarget) (int, error) {
	total := 0
	for {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return total, fmt.Errorf("begin PSK backfill for %s: %w", target.table, err)
		}
		count, batchErr := backfillPresharedKeyBatch(ctx, tx, cipher, target)
		if batchErr != nil {
			_ = tx.Rollback(ctx)
			return total, batchErr
		}
		if err := tx.Commit(ctx); err != nil {
			return total, fmt.Errorf("commit PSK backfill for %s: %w", target.table, err)
		}
		total += count
		if count < presharedKeyBackfillBatchSize {
			return total, nil
		}
	}
}

func backfillPresharedKeyBatch(ctx context.Context, tx pgx.Tx, cipher *dataencryption.Cipher, target presharedKeyBackfillTarget) (int, error) {
	query := fmt.Sprintf(`
		SELECT id, preshared_key
		FROM %s
		WHERE preshared_key <> '' AND preshared_key_ciphertext IS NULL
		ORDER BY id
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, target.table)
	rows, err := tx.Query(ctx, query, presharedKeyBackfillBatchSize)
	if err != nil {
		return 0, fmt.Errorf("select legacy PSK rows from %s: %w", target.table, err)
	}
	type legacyRow struct {
		id        uuid.UUID
		plaintext string
	}
	batch := make([]legacyRow, 0, presharedKeyBackfillBatchSize)
	for rows.Next() {
		var row legacyRow
		if err := rows.Scan(&row.id, &row.plaintext); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan legacy PSK row from %s: %w", target.table, err)
		}
		batch = append(batch, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate legacy PSK rows from %s: %w", target.table, err)
	}
	rows.Close()

	for _, row := range batch {
		ciphertext, version, err := cipher.SealPresharedKey(target.scope, row.id, row.plaintext)
		if err != nil {
			return 0, fmt.Errorf("encrypt legacy PSK row in %s: %w", target.table, err)
		}
		verified, err := cipher.OpenPresharedKey(target.scope, row.id, version, ciphertext)
		if err != nil || subtle.ConstantTimeCompare([]byte(verified), []byte(row.plaintext)) != 1 {
			return 0, fmt.Errorf("verify legacy PSK row in %s: %w", target.table, errors.Join(dataencryption.ErrInvalidCiphertext, err))
		}
		update := fmt.Sprintf(`
			UPDATE %s
			SET preshared_key = '', preshared_key_ciphertext = $2, preshared_key_version = $3
			WHERE id = $1 AND preshared_key <> '' AND preshared_key_ciphertext IS NULL`, target.table)
		tag, err := tx.Exec(ctx, update, row.id, ciphertext, version)
		if err != nil {
			return 0, fmt.Errorf("store encrypted PSK row in %s: %w", target.table, err)
		}
		if tag.RowsAffected() != 1 {
			return 0, fmt.Errorf("store encrypted PSK row in %s: concurrent state change", target.table)
		}
	}
	return len(batch), nil
}
