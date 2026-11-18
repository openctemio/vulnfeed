# Advisory cards

One JSON file per card, named after its id (`OCA-YYYY-NNNN.json`). The format,
the review rules and how a card reaches a release are in the repository
README, section "Advisory cards". Check a change with:

    go run ./cmd/vulnfeed cards check cards

Rules for authors:

- Public facts only, each citing a public source (vendor advisory, CVE record,
  CERT report). Never paste proof-of-concept code or exploit details: a link
  and its title are the most a card holds.
- A new card starts with `"review": {"state": "in_review", "author": "<handle>"}`.
  Only a reviewer sets `reviewed`.
- Never delete a card. Correct it with a new revision and a history note, or
  withdraw it with a reason.
