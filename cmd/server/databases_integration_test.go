//go:build integration

package main

import (
	"context"
	"os"
	"testing"
)

// Connector transactions call identity checks while holding a connection, so the two modules
// must never share a pool: a shared pool deadlocks once enough transactions are open (see
// Databases). Found by the relay load test at 2,000 sockets.
func TestModulesUseSeparateConnectionPools(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_TEST_URL")
	if databaseURL == "" {
		databaseURL = "postgres://opencode_remote:local-development-only@127.0.0.1:5432/opencode_remote?sslmode=disable"
	}
	databases, err := SetupDatabase(context.Background(), Config{DatabaseURL: databaseURL})
	if err != nil {
		t.Skipf("PostgreSQL integration database unavailable: %v", err)
	}
	defer databases.Close()
	identityPool, err := databases.Identity.DB()
	if err != nil {
		t.Fatal(err)
	}
	connectorPool, err := databases.Connectors.DB()
	if err != nil {
		t.Fatal(err)
	}
	if identityPool == connectorPool {
		t.Fatal("identity and connectors share a connection pool")
	}
	if databases.Health != connectorPool {
		t.Fatal("readiness should check the pool relay traffic depends on")
	}
}
