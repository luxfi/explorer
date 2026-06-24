package main

// Runtime proof of the vfs mount wiring (vfsmount.go) and the SQLite-url
// derivation (services.go). FUSE is NOT exercised here — this host may lack
// macFUSE/fuse-t, and the point of these tests is the EXPLORER-side glue:
//
//   1. setupVFS with a file:// backend returns a usable mountpoint and a
//      SQLite database created under it opens, writes, and integrity-checks.
//      (Without the `fuse` tag, mount.Mount returns a build-tag error and we
//      degrade to a plain local directory — these tests assert that fallback
//      still yields a working SQLite path, which is the floor we must hold.)
//   2. resolveServices stamps a DB-backed service with
//      sqlite://<mountpoint>/<svc>.db?mode=rwc and leaves stateless services
//      and explicitly-configured urls untouched.
//
// The deeper "SQLite bytes survive the encrypted vfs block layer" proof lives
// in github.com/hanzoai/vfs (TestSQLiteRoundTrip, file:// backend) and, with
// FUSE present, TestFUSESQLite. The launcher's "connect to sqlite, no postgres
// CREATE DATABASE" proof lives in blockscout-service-launcher database.rs
// (sqlite_tests). Together they cover the stack end to end.

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSetupVFSFileBackendYieldsUsableSQLitePath(t *testing.T) {
	dataDir := t.TempDir()
	storeDir := t.TempDir()

	cfg := VFSConfig{
		Enabled: true,
		Backend: "file://" + storeDir, // s3:// is a pure config swap (both openers registered)
		// Mountpoint empty => <dataDir>/vfs; AgeKeyFile empty => ephemeral key.
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mountpoint, cleanup, err := setupVFS(ctx, cfg, dataDir)
	if err != nil {
		t.Fatalf("setupVFS: %v", err)
	}
	defer func() { _ = cleanup() }()

	if mountpoint == "" {
		t.Fatal("setupVFS returned empty mountpoint while enabled")
	}
	wantMount := filepath.Join(dataDir, "vfs")
	if mountpoint != wantMount {
		t.Fatalf("mountpoint = %q, want %q", mountpoint, wantMount)
	}

	// A SQLite DB created under the mountpoint must be fully usable. Without
	// FUSE this is a plain directory; with FUSE it is the vfs mount — either
	// way the explorer writes the same path, which is what we assert.
	dbPath := filepath.Join(mountpoint, "stats.db")
	dsn := "file:" + dbPath + "?mode=rwc"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE charts (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("CREATE: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO charts (name) VALUES ('totalBlocks')`); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM charts`).Scan(&n); err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	var ok string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&ok); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if !strings.EqualFold(ok, "ok") {
		t.Fatalf("integrity_check = %q, want ok", ok)
	}
}

func TestSetupVFSDisabledIsNoop(t *testing.T) {
	mountpoint, cleanup, err := setupVFS(context.Background(), VFSConfig{Enabled: false}, t.TempDir())
	if err != nil {
		t.Fatalf("setupVFS disabled: %v", err)
	}
	defer func() { _ = cleanup() }()
	if mountpoint != "" {
		t.Fatalf("disabled vfs must return empty mountpoint, got %q", mountpoint)
	}
}

func TestResolveServicesStampsSQLiteUrlOnVFSMount(t *testing.T) {
	enabled := true
	cfg := ServicesConfig{
		Enabled: true,
		Services: []ServiceConfig{
			{Name: "sig-provider", Enabled: &enabled},                 // stateless: no url ever
			{Name: "stats", Enabled: &enabled},                        // DB-backed: gets sqlite url on mount
			{Name: "multichain-aggregator", Enabled: &enabled},        // DB-backed: gets sqlite url on mount
			{Name: "stats", Prefix: "stats2", Enabled: &enabled, DatabaseURL: "postgresql://u:p@h:5432/stats"}, // explicit url wins
		},
	}
	mount := "/var/lib/explorer/vfs"
	got := resolveServices(cfg, mount)

	urlByPrefix := map[string]string{}
	for _, s := range got {
		// re-extract database.url from the rendered settings JSON
		urlByPrefix[s.Prefix] = extractDBURL(t, s.SettingsJSON)
	}

	if u := urlByPrefix["sig"]; u != "" {
		t.Fatalf("stateless sig-provider must have no database.url, got %q", u)
	}
	wantStats := "sqlite://" + filepath.Join(mount, "stats.db") + "?mode=rwc"
	if u := urlByPrefix["stats"]; u != wantStats {
		t.Fatalf("stats database.url = %q, want %q", u, wantStats)
	}
	wantMC := "sqlite://" + filepath.Join(mount, "multichain-aggregator.db") + "?mode=rwc"
	if u := urlByPrefix["multichain"]; u != wantMC {
		t.Fatalf("multichain database.url = %q, want %q", u, wantMC)
	}
	if u := urlByPrefix["stats2"]; u != "postgresql://u:p@h:5432/stats" {
		t.Fatalf("explicit url must win, got %q", u)
	}

	// And with NO mountpoint, DB-backed services without an explicit url get none.
	for _, s := range resolveServices(cfg, "") {
		if s.Prefix == "stats" {
			if u := extractDBURL(t, s.SettingsJSON); u != "" {
				t.Fatalf("no vfs mount => stats must have no database.url, got %q", u)
			}
		}
	}
}

// extractDBURL pulls database.url out of a rendered settings JSON, or "" if absent.
func extractDBURL(t *testing.T, settingsJSON string) string {
	t.Helper()
	if settingsJSON == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(settingsJSON), &m); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	dbAny, ok := m["database"]
	if !ok {
		return ""
	}
	dbMap, ok := dbAny.(map[string]any)
	if !ok {
		return ""
	}
	u, _ := dbMap["url"].(string)
	return u
}
