// Command vulnfeed builds, signs and verifies OpenCTEM vulnerability
// bundles (RFC-066 §5.5), and manages the signing keys.
//
//	vulnfeed build  --out DIR [--prev DIR] [--root-key-id ID] [--allow-mass-change]
//	vulnfeed sign   --dir DIR --keyset FILE --root-key-id ID     (key in $VULNFEED_SIGNING_KEY)
//	vulnfeed verify --dir DIR --root-key-id ID [--applied N] [--allow-expired]
//	vulnfeed keys root-init --out FILE
//	vulnfeed keys gen --out FILE
//	vulnfeed keys sign-keyset --root FILE --key PUBLIC_KEY [--key ...] --version N [--days 180] --out FILE
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/openctemio/vulnfeed/internal/bundle"
	"github.com/openctemio/vulnfeed/internal/collect"
	"github.com/openctemio/vulnfeed/internal/dsse"
	"github.com/openctemio/vulnfeed/internal/nvd"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vulnfeed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vulnfeed build|sign|verify|keys ...")
	}
	switch args[0] {
	case "build":
		return cmdBuild(ctx, args[1:])
	case "sign":
		return cmdSign(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	case "keys":
		return cmdKeys(args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

func cmdBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	out := fs.String("out", "", "output directory")
	prevDir := fs.String("prev", "", "previous release (verified before use)")
	root := fs.String("root-key-id", os.Getenv("VULNFEED_ROOT_KEY_ID"), "pinned root key id")
	mass := fs.Bool("allow-mass-change", false, "publish even when the guard refuses")
	trial := fs.Duration("trial-since", 0, "without --prev: read only CVEs modified in this window (a trial, never published)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("build: --out is required")
	}
	now := time.Now().UTC()
	var prev *bundle.Snapshot
	if *prevDir != "" {
		v, err := bundle.VerifyDir(*prevDir, bundle.VerifyOptions{PinnedRoot: *root, Now: now, AllowExpired: true, SkipRecordChk: true})
		if err != nil {
			return fmt.Errorf("previous release: %w", err)
		}
		if prev, err = bundle.ReadRecords(*prevDir, v.Snapshot); err != nil {
			return fmt.Errorf("previous release: %w", err)
		}
		logf("previous release: sequence %d, %d vulnerabilities", prev.Sequence, len(prev.Vulns))
	}
	next, err := collect.Build(ctx, prev, nvd.NewClient(os.Getenv("NVD_API_KEY")),
		collect.Options{Now: now, AllowMassChange: *mass, Since: sinceOf(now, *trial), Log: logf})
	if err != nil {
		return err
	}
	snap, delta, _, err := bundle.Write(*out, prev, next, bundle.WriteOptions{Now: now,
		Collector: bundle.Collector{Version: version, Commit: os.Getenv("GITHUB_SHA")}})
	if err != nil {
		return err
	}
	logf("built sequence %d: %d vulnerabilities, %d ranges, %d products", snap.Sequence, snap.Stats.Vulns, snap.Stats.Ranges, snap.Stats.Products)
	if delta != nil {
		logf("delta from %d: %d vulnerabilities, +%d -%d ranges", delta.BaseSequence, delta.Stats.Vulns, delta.Stats.RangesAdded, delta.Stats.RangesRemoved)
	}
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	dir := fs.String("dir", "", "bundle directory")
	keyset := fs.String("keyset", "keys/keyset.dsse.json", "key set envelope")
	root := fs.String("root-key-id", os.Getenv("VULNFEED_ROOT_KEY_ID"), "pinned root key id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("VULNFEED_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("sign: VULNFEED_SIGNING_KEY must be a base64 32-byte Ed25519 seed")
	}
	ks, err := os.ReadFile(*keyset)
	if err != nil {
		return err
	}
	return bundle.Sign(*dir, ed25519.NewKeyFromSeed(seed), ks, *root, time.Now())
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("dir", "", "bundle directory")
	root := fs.String("root-key-id", os.Getenv("VULNFEED_ROOT_KEY_ID"), "pinned root key id")
	applied := fs.Uint64("applied", 0, "last applied sequence")
	expired := fs.Bool("allow-expired", false, "accept an expired bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := bundle.VerifyDir(*dir, bundle.VerifyOptions{PinnedRoot: *root, AppliedSeq: *applied, Now: time.Now(), AllowExpired: *expired})
	if err != nil {
		return err
	}
	if bundle.HasV2(*dir) {
		if err := bundle.VerifyV2(*dir, v.KeySet, time.Now()); err != nil {
			return err
		}
		logf("verified bundle v2 (sequence %d)", v.Latest.Sequence)
	}
	logf("verified sequence %d (snapshot %d vulnerabilities, %d ranges; key set v%d)", v.Latest.Sequence,
		v.Snapshot.Stats.Vulns, v.Snapshot.Stats.Ranges, v.KeySet.Version)
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("keys: root-init|gen|sign-keyset")
	}
	switch args[0] {
	case "root-init", "gen":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		out := fs.String("out", "", "file to write the private seed to (mode 0600; keep a root offline)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("keys: --out is required")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("key id:     %s\npublic key: %s\nseed file:  %s\n", dsse.KeyID(pub), base64.StdEncoding.EncodeToString(pub), *out)
		return nil
	case "sign-keyset":
		fs := flag.NewFlagSet("sign-keyset", flag.ContinueOnError)
		rootFile := fs.String("root", "", "root seed file")
		ver := fs.Uint64("version", 0, "key set version (higher than the current one)")
		days := fs.Int("days", 180, "validity in days (at most 180)")
		out := fs.String("out", "keys/keyset.dsse.json", "output")
		var keys multi
		fs.Var(&keys, "key", "base64 public key of an online signing key (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		raw, err := os.ReadFile(*rootFile)
		if err != nil {
			return err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("keys: the root file is not a base64 32-byte seed")
		}
		pubs := make([]ed25519.PublicKey, 0, len(keys))
		for _, k := range keys {
			b, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(b) != ed25519.PublicKeySize {
				return fmt.Errorf("keys: %q is not a base64 Ed25519 public key", k)
			}
			pubs = append(pubs, b)
		}
		env, err := dsse.SignKeySet(ed25519.NewKeyFromSeed(seed), *ver, time.Now(), time.Duration(*days)*24*time.Hour, pubs)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, env, 0o644)
	}
	return fmt.Errorf("keys: unknown command %q", args[0])
}

func sinceOf(now time.Time, d time.Duration) time.Time {
	if d <= 0 {
		return time.Time{}
	}
	return now.Add(-d)
}
