# SPEC — tabula (proof of non-knowledge)

## Chain

`Chain` — append-only, hash-chained; entries carry `seq`,
`content_hash` (sha256 commitment, never content), `prev_hash`, `hash`,
`ts`. `verify()` recomputes linkage and hashes.

## Proof

`prove_absence(content)` / `prove_absence_hash(commitment)`:

```json
{
  "query_hash": "sha256 of the queried content",
  "prover": "pubkey", "head": "chain tip at scan time",
  "entries_scanned": 0, "ts": 0,
  "signature": "ed25519 over canonical body",
  "verified": true
}
```

Semantics:

- If the query hash matches any entry's `content_hash`, the API returns
  `KnowledgeFound { seq }` — a false proof cannot be signed.
- The proof pins the exact history scanned: head + entry count.

## `proof.check(chain)`

1. `chain.verify()` — linkage intact.
2. `chain.head() == proof.head` — same history.
3. `chain.len() == entries_scanned` — same extent.
4. No entry's `content_hash == query_hash` — absence, recomputed.
5. Signature over the proof body — prover attestation.

## Invariants

- Only sha256 commitments appear in the chain — a proof discloses the
  query, never history.
- Proving absence from *history* ≠ proving absence from a mind; the
  boundary is stated, not hidden.
