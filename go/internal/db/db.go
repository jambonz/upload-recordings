// Package db looks up an account's recording configuration in the jambonz
// MySQL database.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Account is the subset of the accounts row the recorder needs.
type Account struct {
	RecordFormat     string
	BucketCredential string // encrypted
	EvalCredential   string // encrypted; empty when the integration is off
}

// DB wraps the connection pool. A DB whose configuration was incomplete is
// still usable: every call returns the configuration error, so the service
// starts and reports the problem instead of crash-looping.
type DB struct {
	pool *sql.DB
	err  error
}

// Open builds the pool from MYSQL_HOST, MYSQL_USER, MYSQL_DATABASE and
// JAMBONES_MYSQL_PASSWORD (falling back to MYSQL_PASSWORD). It does not
// connect; call Ping for that.
func Open() *DB {
	host, user, database := os.Getenv("MYSQL_HOST"), os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_DATABASE")
	// Every other jambonz component reads JAMBONES_MYSQL_PASSWORD; prefer it
	// so a single shared secret reaches this process too. MYSQL_HOST is
	// deliberately not given the same treatment: it is per-role (this
	// service belongs on the reader endpoint).
	password := os.Getenv("JAMBONES_MYSQL_PASSWORD")
	if password == "" {
		password = os.Getenv("MYSQL_PASSWORD")
	}
	if host == "" || user == "" || password == "" || database == "" {
		return &DB{err: errors.New("missing one or more required environment variables: MYSQL_HOST, MYSQL_USER, " +
			"JAMBONES_MYSQL_PASSWORD (or MYSQL_PASSWORD), MYSQL_DATABASE")}
	}
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = addr(host)
	cfg.User = user
	cfg.Passwd = password
	cfg.DBName = database
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return &DB{err: err}
	}
	pool := sql.OpenDB(connector)
	pool.SetMaxOpenConns(10) // the C++ service's pool size
	pool.SetMaxIdleConns(10)
	pool.SetConnMaxIdleTime(4 * time.Minute)
	return &DB{pool: pool}
}

// addr accepts the forms the C++ connector did: host, host:port and
// tcp://host[:port].
func addr(host string) string {
	host = strings.TrimPrefix(host, "tcp://")
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, "3306")
	}
	return host
}

// Ping verifies that the database is reachable with the configured
// credentials.
func (d *DB) Ping(ctx context.Context) error {
	if d.err != nil {
		return d.err
	}
	return d.pool.PingContext(ctx)
}

// Lookup fetches the recording configuration for accountSid.
func (d *DB) Lookup(ctx context.Context, accountSid string) (Account, error) {
	if d.err != nil {
		return Account{}, d.err
	}
	var format, bucket, eval sql.NullString
	err := d.pool.QueryRowContext(ctx,
		"SELECT record_format, bucket_credential, eval_credential FROM accounts WHERE account_sid = ?",
		accountSid).Scan(&format, &bucket, &eval)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, fmt.Errorf("account not found for SID: %s", accountSid)
	}
	if err != nil {
		return Account{}, err
	}
	return Account{RecordFormat: format.String, BucketCredential: bucket.String, EvalCredential: eval.String}, nil
}

// Close releases the pool.
func (d *DB) Close() {
	if d.pool != nil {
		d.pool.Close()
	}
}
