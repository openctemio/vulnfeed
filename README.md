# vulnfeed

The vulnerability collector of [OpenCTEM](https://github.com/openctemio/openctem).
Once a day it reads the public vulnerability sources, normalises them into
OpenCTEM's corpus model (products, vulnerabilities and affected version
ranges), validates every record, signs the result and publishes it as a
GitHub Release. OpenCTEM platforms never call the sources themselves: they
download (or, air-gapped, upload) a bundle, verify it and import it.

Design: OpenCTEM RFC-066 §5.5, *Feed: collector and signed bundles*.

## Using it with your platform

Nothing is installed on your hosts: the platform downloads (or, air-gapped,
reads) a release, verifies it against the root key id you pin and imports
it. Set `VULNFEED_ROOT_KEY_ID` on the API (from `keys/root-keyid.txt`); without
it no bundle is imported. Setup, air-gapped use and how to check the import:
[Vulnerability and program feeds](https://docs.openctem.io/operations/feeds/)
on docs.openctem.io.

No release is published yet: the first one follows the key ceremony in
[`keys/README.md`](keys/README.md).

## What a release contains

| Asset | Content |
|---|---|
| `latest.dsse.json` | signed pointer: sequence, tag, snapshot and delta manifests, expiry |
| `snapshot.manifest.dsse.json` | signed manifest of the full snapshot (files, SHA-256, sizes, record counts, sources, stats) |
| `snapshot-{products,vulns,ranges}.jsonl.gz` | the full corpus |
| `delta.manifest.dsse.json`, `delta-*.jsonl.gz` | what changed since the previous sequence (each touched vulnerability with its complete new range set) |
| `keyset.dsse.json` | the key set the manifests are signed under |
| `aliases.manifest.dsse.json` | signed manifest of the alias dictionary: the bundle sequence it belongs to, the dictionary version, the files below (SHA-256, sizes, counts) and the coverage stats |
| `aliases.jsonl.gz` | the alias dictionary: CNA vendor/product names (and alternate CPE products) → canonical CPE product |
| `aliases-state.jsonl.gz` | what each published CVE List record says about product identity (the learner's input, carried from release to release) |
| `latest.v2.dsse.json` | bundle v2: signed pointer that pins the digest of each v2 manifest |
| `snapshot.v2.manifest.dsse.json`, `delta.v2.manifest.dsse.json` | bundle v2: signed manifests listing, per record stream (`products`, `vulns`, `ranges`), the chunks with SHA-256, sizes, record counts and first and last record id |
| `sha256-<hex>.jsonl.gz` | bundle v2 chunks: gzip JSON Lines of the same records as v1, named by their digest |

Bundle v2 (OpenCTEM RFC-070) carries the same records as v1 in chunks of
about 2,000 records, split by record id: the same data always gives the
same chunks, and a changed vulnerability changes few chunks, so a consumer
fetches only the chunks it does not have. It is signed with the same keys
and key set as v1. v1 stays in every release for one release cycle and is
then removed; read v2 with the `pkg/transfer/bundle` consumer of the
OpenCTEM SDK. `vulnfeed verify` checks both formats.

A platform reads
`https://github.com/openctemio/vulnfeed/releases/latest/download/latest.dsse.json`
and the files of the release it names.

Record formats (one JSON object per line):

```json
{"key":"cpe:a:f5:nginx","part":"a","vendor":"f5","name":"nginx","cpe_vendor":"f5","cpe_product":"nginx"}
{"id":"CVE-2021-23017","status":"Modified","published":"…","modified":"…","description":"…","cvss":{"version":"3.1","score":7.7,"vector":"CVSS:3.1/…"},"severity":"high","cwes":["CWE-193"]}
{"vuln":"CVE-2021-23017","product":"cpe:a:f5:nginx","scheme":"generic","start":"0.6.18","start_incl":true,"end":"1.20.1","end_incl":false,"edition":"","target":"","source":"nvd"}
```

A range is an exact version, or a start and/or end bound with inclusive
flags, or neither ("all versions"); a vulnerability is affected when any of
its ranges covers the version. `condition` names a platform the product must
run on.

## Sources

| Source | What it gives | How it is read |
|---|---|---|
| NVD CVE API 2.0 | CVE records, CPE configurations (ranges with source `nvd`), scores | CVEs modified since the previous build, in windows of at most 120 days; at most every two hours (`--nvd-min-interval`), a build in between keeps the NVD cursor |
| CVE List (CVE JSON 5.x, `CVEProject/cvelistV5`) | the CNA's record: state (published or rejected), description, dates, CNA score (CVSS 4.0, 3.1, 3.0), CWEs, affected products and versions (ranges with source `cve5`) | records changed by commits since the previous build, each checked against its git blob id; the first build, or a window with more changes than an incremental read takes, reads the daily baseline archive (checked against its published SHA-256) and the changes since |

Merge precedence (`internal/collect/merge.go`):

| Field | Winner |
|---|---|
| state | rejected when either source says so; a CVE List record published again restores the CVE |
| description, published date | the CVE List (the CNA's own text); NVD's copy when the CVE List record was not read in that build |
| modified | the later of the two |
| score, severity, CWEs | NVD when it has them; the CNA's only fill a CVE NVD has none for |
| affected ranges | NVD's CPE configurations whenever NVD has any for the CVE; the CNA's affected data only for a CVE without them |

A CVE's ranges come from one source, never a mix. CNA affected data becomes
ranges only where it is comparable: an `affected` statement with a CPE, or a
vendor and product name (written in the CPE naming convention, legal-form
words such as "Inc." or "Corporation" and parenthesised qualifiers dropped;
see the alias dictionary below), and a
version, `lessThan` or `lessThanOrEqual` bound of type semver, custom or
none. Statements with status changes, other version orderings (git, rpm,
maven, ...), commit hashes, packages (`packageName`) and placeholder names
are dropped, never widened to "all versions". So is a range with no bound
(`0` or `*` up to `*`), and an open-ended range (`lessThan: "*"`) in an item
that also states unaffected versions inside it (backported fixes), since the
bundle cannot carry that subtraction. The default status never becomes a
range.

Beyond what becomes ranges, each CVE List record keeps, cleaned and capped,
its references, the CNA's complete affected list (vendor, product, package
name and collection URL, CPEs, platforms, default status, every version
statement with its type, bounds and status changes) and its ADP containers
(score, CWEs, affected items with CPEs, SSVC decision points), in
`cve5.Record` (`References`, `Affected`, `ADP`). They are not yet carried:
the record format is decoded strictly by platforms, so new fields (references,
package products, advisory aliases, KEV and EPSS) come with the next record
format version. CISA KEV and EPSS are synced by the platform itself until
then. OSV (package ecosystems) needs package (purl) products and ecosystem
version schemes in that format and is not collected yet.

Terms and attribution: `NOTICE`.

## Alias dictionary

Most new CVE records carry no CPE: they name the product only by the CNA's
vendor and product strings, which often differ from the CPE names platforms
see ("Google Inc." / "Chrome", "Linux" / "Linux" for the kernel). The alias
dictionary (`internal/alias`, OpenCTEM RFC-066 §5.6) maps those names to
the canonical CPE product:

| Basis | Rule |
|---|---|
| `curated` | a reviewed entry in `internal/alias/curated.tsv`; never overridden |
| `learned` | the name and one CPE product appear for the same affected item (its own CPEs, the ADP's CPEs for it, or the only NVD product of a CVE with one unnamed CNA product) in at least 3 CVEs, with at least 90% agreement |
| `part` | the same vendor:product is a known CPE product under another part (operating system, hardware) |
| `vendor` | the CNA vendor maps to a CPE vendor (curated, or learned from at least 5 CVEs at 90%) and vendor:product is a known CPE product |

Every build learns from the CVE List records it reads (kept per CVE in
`aliases-state.jsonl.gz`, so a record read again replaces its evidence),
rewrites the CVE List ranges of a mapped name to the canonical product, and
publishes the entries with a version that grows whenever they change. A name
nothing resolves keeps its name-derived product (the CVE is published, and
matches once a later dictionary resolves it) and is listed in the stats.
Coverage, in the stats and the build log, is the share of published CVE List
records that name a CPE product or a resolved name, or name no product at
all (placeholders such as "n/a", or only a package name): the target is 95%.

The inputs are public advisory text: names are sanitised and normalised,
malformed CPE values dropped, every learned mapping needs repeated agreeing
evidence, curated entries win, and the dictionary is signed with the bundle
keys and bound to the release sequence.

## Verifying a bundle yourself

```sh
go build -o vulnfeed ./cmd/vulnfeed
gh release download --repo openctemio/vulnfeed --dir bundle
./vulnfeed verify --dir bundle --root-key-id "$(cat keys/root-keyid.txt)"
```

Bundles are reproducible from the public sources: rebuilding from the same
previous release and source data gives byte-identical record files.

## Building locally

```sh
go test ./...
go build -o vulnfeed ./cmd/vulnfeed
./vulnfeed build --out out --trial-since 24h     # a trial: CVEs modified in the last day
```

`GITHUB_TOKEN` (any token, no scopes needed) raises the GitHub API rate
limit for the CVE List; `--cve-list=false` builds from NVD alone.

A key is needed only to sign; see `keys/README.md`.

## Security

See [SECURITY.md](SECURITY.md) for the trust model (offline root, key sets,
rollback and freeze protection) and how to report a problem.

## Licence

Apache-2.0 (the code). The data keeps its sources' terms; see `NOTICE`.
