# Keys

This directory holds only public material:

| File | What |
|---|---|
| `root-keyid.txt` | key id of the offline root (`SHA256:…`); platforms pin it |
| `keyset.dsse.json` | the current key set, signed by the root |

## First setup (maintainer, on an offline machine)

```sh
go build -o vulnfeed ./cmd/vulnfeed

# 1. The offline root. Keep root.key offline (hardware-backed storage or an
#    encrypted offline medium, plus a backup). It never goes to CI.
./vulnfeed keys root-init --out root.key          # prints the root key id

# 2. The online signing key.
./vulnfeed keys gen --out signing.key             # prints its public key

# 3. The key set: the root allows the online key for up to 180 days.
./vulnfeed keys sign-keyset --root root.key --key <signing public key> --version 1 --days 180 --out keys/keyset.dsse.json
```

Then:

- commit `keys/root-keyid.txt` (the root key id) and `keys/keyset.dsse.json`;
- create the GitHub environment **`publish`**: deployment branches limited
  to the default branch; add the secret **`VULNFEED_SIGNING_KEY`** with the
  content of `signing.key`; delete `signing.key` from the machine;
- optionally add the repository secret **`NVD_API_KEY`** (a free NVD API
  key makes the first build much faster);
- give OpenCTEM platforms the root key id (`VULNFEED_ROOT_KEY_ID`).

## Rotation and revocation

Before the key set expires, or at once if the online key may have leaked:
generate a new online key, sign a key set with a **higher version** listing
only the keys still trusted, commit it and replace the environment secret.
Platforms that have seen the new version refuse the older key set from then
on.

If the root itself is compromised, generate a new root and have every
platform pin its new key id.
