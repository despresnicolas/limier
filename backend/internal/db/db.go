// Package db opens the SQLite database and runs schema migrations (goose for Limier tables, River's own migrator for the queue).
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"net/url"

	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riversqlite"
	"github.com/riverqueue/river/rivermigrate"
	_ "modernc.org/sqlite" // pure-Go driver "sqlite": no cgo, so cross-builds stay simple
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open opens (and creates) the SQLite file at path.
//
// One writer at a time: _txlock=immediate takes the write lock at BEGIN, so a transaction never fails
// halfway when it upgrades from read to write, and busy_timeout makes other writers wait (10 s) instead
// of failing with SQLITE_BUSY. WAL lets readers run during a write, so the pool keeps several connections
// and API reads don't queue behind River workers. Times are written as UTC text that sorts in time order
// (see migrations/00001_init.sql); _texttotime turns expression results such as date(...) back into time.Time.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	q := url.Values{}
	for _, p := range []string{"foreign_keys(1)", "journal_mode(WAL)", "synchronous(NORMAL)", "busy_timeout(10000)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	q.Set("_time_format", "sqlite")
	q.Set("_timezone", "UTC")
	q.Set("_texttotime", "1")
	pool, err := sql.Open("sqlite", path+"?"+q.Encode()) // a plain path, not a file: URI: no escaping of spaces
	if err != nil {
		return nil, err
	}
	// shortcut: 8 connections is plenty for one user and a few workers; raise it if API reads ever queue.
	pool.SetMaxOpenConns(8)
	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	return pool, nil
}

// Migrate applies River and Limier migrations.
func Migrate(ctx context.Context, pool *sql.DB) error {
	migrator, err := rivermigrate.New(riversqlite.New(pool), nil)
	if err != nil {
		return err
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, pool, mustSub(migrations, "migrations"))
	if err != nil {
		return err
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("limier migrations: %w", err)
	}
	return nil
}
