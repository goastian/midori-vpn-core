package repo

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ListOptions struct {
	Limit  int
	Offset int
	Search string
	Status string
	Sort   string
	Order  string
}

type pageScanner[T any] func(pgx.Rows) (T, error)

func queryPage[T any](
	ctx context.Context,
	pool *pgxpool.Pool,
	countSQL string,
	listSQL string,
	filterArgs []any,
	limit int,
	offset int,
	scan pageScanner[T],
) ([]T, int, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, fmt.Errorf("begin list snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var total int
	if err := tx.QueryRow(ctx, countSQL, filterArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count list rows: %w", err)
	}
	listArgs := append(append(make([]any, 0, len(filterArgs)+2), filterArgs...), limit, offset)
	rows, err := tx.Query(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query list rows: %w", err)
	}
	defer rows.Close()

	items := make([]T, 0, min(limit, total))
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate list rows: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("commit list snapshot: %w", err)
	}
	return items, total, nil
}

func listWhere(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

func listDirection(order string) string {
	if order == "asc" {
		return "ASC"
	}
	return "DESC"
}
