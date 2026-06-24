package main

// vfsmount.go — back the in-process services' SQLite databases with
// github.com/hanzoai/vfs, a block-level PQ-encrypted virtual filesystem over a
// pluggable object backend (`s3://…` in prod, `file://…` for local dev).
//
// One concern, decomplected from everything else:
//
//	config (VFSConfig)  →  setupVFS()  →  a local mountpoint path
//
// The mountpoint is a real directory the OS can read/write. When the binary is
// built with `-tags fuse` (and macFUSE/fuse-t or Linux kernel FUSE is present),
// that directory is a live FUSE mount whose every 4 KiB block is blake3-hashed,
// age-encrypted, and stored on the backend — so the SQLite files the services
// write land in S3 with zero local persistence. Without the `fuse` tag,
// vfs/pkg/mount's stub returns a build-tag error; we log it and fall back to a
// plain local directory at the same path, so the SQLite-on-mountpoint wiring is
// identical and the only thing lost is the S3 backing (a build-tag swap, not a
// code change). This is the same on/off seam as ffi_on.go / ffi_off.go.
//
// The DB url rewrite (sqlite://<mountpoint>/<svc>.db?mode=rwc) lives in
// services.go's resolution path so both the FFI launcher and the proxy read one
// resolved value (DRY). setupVFS only produces the mountpoint.

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/luxfi/age"

	"github.com/hanzoai/vfs"
	"github.com/hanzoai/vfs/pkg/backend"
	_ "github.com/hanzoai/vfs/pkg/backend/file" // register file:// opener
	_ "github.com/hanzoai/vfs/pkg/backend/s3"   // register s3:// opener
	"github.com/hanzoai/vfs/pkg/mount"
)

// VFSConfig configures the optional vfs mount that backs service SQLite DBs.
// Default (Enabled=false) is a no-op: services use whatever DatabaseURL the
// chains.yaml gives them (or none), exactly as before.
type VFSConfig struct {
	// Enabled is the master switch. False (default) => no mount; the explorer is
	// unchanged. True => setupVFS mounts Backend at Mountpoint and DB-backed
	// services get a sqlite:// url under it.
	Enabled bool `yaml:"enabled"`
	// Backend is the vfs object-store URL. `s3://<bucket>/<prefix>?region=…`
	// (optionally `&endpoint=https://s3.hanzo…` for the hanzoai/s3 SeaweedFS
	// gateway) in prod; `file://<dir>` for local dev. The s3:// ↔ file:// swap
	// is config only — no code change (both openers are registered above).
	Backend string `yaml:"backend"`
	// Mountpoint is the local directory the vfs is mounted at and under which
	// service SQLite files live. Empty => "<data_dir>/vfs". The directory is
	// created if absent.
	Mountpoint string `yaml:"mountpoint"`
	// AgeKeyFile is a path to an age identity (X25519, optionally hybrid PQ via
	// ML-KEM-768) used to encrypt every block. Empty => an ephemeral identity is
	// generated for this run (blocks are still encrypted at rest on the backend;
	// the data does not survive a restart with a fresh key — fine for a cache /
	// prototype, set a stable key for durable storage).
	AgeKeyFile string `yaml:"age_key_file"`
}

// setupVFS mounts the configured backend and returns the local mountpoint that
// service SQLite databases should live under, plus a cleanup func that tears the
// mount down. When cfg.Enabled is false it returns ("", noop-cleanup, nil) and
// the caller leaves DB urls untouched.
//
// The mount runs in a background goroutine (mount.Mount blocks serving FUSE ops
// until ctx is cancelled). We create the mountpoint directory regardless so the
// path is always usable — under FUSE it becomes the mount root; without FUSE it
// is a plain local dir and SQLite still works (sans S3 backing).
func setupVFS(ctx context.Context, cfg VFSConfig, dataDir string) (string, func() error, error) {
	noop := func() error { return nil }
	if !cfg.Enabled {
		return "", noop, nil
	}

	mountpoint := cfg.Mountpoint
	if mountpoint == "" {
		mountpoint = filepath.Join(dataDir, "vfs")
	}
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return "", noop, fmt.Errorf("vfs: mkdir mountpoint %q: %w", mountpoint, err)
	}

	if cfg.Backend == "" {
		return "", noop, fmt.Errorf("vfs: enabled but no backend url set (e.g. s3://bucket/prefix?region=… or file:///path)")
	}

	be, err := backend.Open(ctx, cfg.Backend)
	if err != nil {
		return "", noop, fmt.Errorf("vfs: open backend %q: %w", cfg.Backend, err)
	}

	id, err := loadOrGenerateAgeIdentity(cfg.AgeKeyFile)
	if err != nil {
		_ = be.Close()
		return "", noop, fmt.Errorf("vfs: age identity: %w", err)
	}
	crypto, err := vfs.NewCrypto([]age.Recipient{id.Recipient()}, []age.Identity{id})
	if err != nil {
		_ = be.Close()
		return "", noop, fmt.Errorf("vfs: crypto: %w", err)
	}

	v, err := vfs.New(vfs.Config{Backend: be, Crypto: crypto})
	if err != nil {
		_ = be.Close()
		return "", noop, fmt.Errorf("vfs: new: %w", err)
	}
	fs, err := vfs.NewFS(ctx, v)
	if err != nil {
		_ = be.Close()
		return "", noop, fmt.Errorf("vfs: newfs: %w", err)
	}

	mountCtx, cancel := context.WithCancel(ctx)
	mounted := make(chan error, 1)
	go func() {
		// mount.Mount blocks until mountCtx is cancelled or the kernel unmounts.
		// Without the `fuse` build tag the stub returns immediately with a
		// build-tag error; with FUSE it serves until cleanup cancels the ctx.
		mounted <- mount.Mount(mountCtx, fs, mountpoint)
	}()

	// Give the mount a brief moment to either fail fast (stub / no macFUSE) or
	// settle into serving (FUSE). We never hard-fail on the stub error — we
	// degrade to the local directory so the SQLite-on-mountpoint path is still
	// exercised; the only thing lost is the block backing (a build-tag swap).
	select {
	case err := <-mounted:
		if err != nil {
			log.Printf("[vfs] FUSE mount unavailable (built without -tags fuse, or no macFUSE/fuse-t): %v", err)
			log.Printf("[vfs] falling back to plain local directory %q — backend %q is NOT block-backed this run", mountpoint, cfg.Backend)
		}
	case <-time.After(250 * time.Millisecond):
		// Still serving after the settle window => FUSE path is live.
		log.Printf("[vfs] mounted backend %q at %q — service SQLite DBs are block-backed", cfg.Backend, mountpoint)
	}

	cleanup := func() error {
		cancel()
		return be.Close()
	}
	return mountpoint, cleanup, nil
}

// loadOrGenerateAgeIdentity loads an age X25519 identity from keyFile, or
// generates an ephemeral one when keyFile is empty. The on-disk format is the
// standard age "AGE-SECRET-KEY-1…" one-line form (filippo.io/age / luxfi/age).
func loadOrGenerateAgeIdentity(keyFile string) (*age.X25519Identity, error) {
	if keyFile == "" {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral identity: %w", err)
		}
		log.Printf("[vfs] no age_key_file set — generated an ephemeral encryption key for this run")
		return id, nil
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", keyFile, err)
	}
	id, err := age.ParseX25519Identity(firstNonCommentLine(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse identity from %q: %w", keyFile, err)
	}
	return id, nil
}

// firstNonCommentLine returns the first non-empty, non-`#` line — age key files
// carry `# created: …` / `# public key: …` comment lines above the secret.
func firstNonCommentLine(s string) string {
	for _, line := range splitLines(s) {
		t := trimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		return t
	}
	return trimSpace(s)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r' || s[j-1] == '\n') {
		j--
	}
	return s[i:j]
}
