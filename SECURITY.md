# Security

## Reporting

Please report vulnerabilities privately to **security@openctem.io** or through
GitHub's private vulnerability reporting on this repository. Do not open a
public issue.

## Trust model

A bundle tells every OpenCTEM platform which software versions are
vulnerable. A forged or stale bundle could hide real vulnerabilities or
raise false ones everywhere, so:

- **Offline root.** An Ed25519 root key, kept offline by the maintainer,
  only signs *key sets*. Platforms pin its key id (`keys/root-keyid.txt`).
- **Key set.** A key set (`keys/keyset.dsse.json`) lists the online signing
  keys, is valid for at most 180 days and has a version that only goes up.
  A platform refuses a key set whose version is lower than one it has
  already accepted, so a revoked key cannot come back.
- **Online key.** The signing key is a secret of the `publish` GitHub
  environment, which only the default branch can deploy to. Only the
  publish job runs there; it signs, verifies and uploads what the build job
  produced. The build job, which talks to the sources, never sees the key.
- **Rollback.** Every bundle has a sequence number. A platform refuses a
  sequence it has already applied, and a delta whose base is not the
  sequence it has.
- **Freeze.** Every manifest and pointer expires 7 days after it was made.
  An expired bundle is refused; platforms warn when no new bundle arrives.
- **Integrity.** The signed manifest holds the SHA-256, size and record
  count of every file; a mismatch refuses the whole bundle.
- **Poisoned data.** The collector validates every record before it signs
  (CVE id, CPE grammar with a concrete vendor and product, comparable
  versions, bounded strings) and refuses to publish when more than 2 % of
  the stored ranges would disappear at once, unless a maintainer overrides
  it after checking the source. Platforms re-validate every record with
  their own parsers and apply the same guard.
- **Size.** Manifests are capped at 1 MiB, files at 512 MiB compressed and
  2 GiB decompressed; records are read one line at a time.

## Key ceremony (maintainers)

See `keys/README.md`. Never commit a private key; the repository holds only
public material (`root-keyid.txt`, `keyset.dsse.json`).
