# tabula

**Proof of non-knowledge — a signed certificate that a datum never appeared in an append-only, hash-chained history.**

Tabula rasa — the blank slate, proven rather than claimed.

## Why this exists

Deletion can be proven (camazotz does that). *Absence* is harder: any log can claim a row was never there by simply not showing it. But a hash-chained ledger can't hide a hit — every entry commits to all previous entries, so editing out a match breaks the chain itself. That makes a committed scan meaningful:

1. Prover walks the whole chain, compares each entry's content commitment to the query hash, recomputes the chain.
2. Signs a `NonKnowledgeProof` pinning the query, the chain head, the entry count, and the scan time.
3. Any holder of the chain replays the scan — the proof is only valid over exactly that history.

## What it proves (and doesn't)

- ✅ "this content-hash never occurred in my history" — independently replayable.
- ❌ "I don't know this fact" — history ≠ a brain; tabula certifies the record, not the mind.
- 🔒 The chain stores sha256 *commitments*, never content — a proof reveals nothing but the query.

## Refusal is a feature

`prove_absence` returns `KnowledgeFound` when the content *is* present — the API cannot sign a false proof. An organism that wants to lie about its past has to break its own chain first, which every verifier would catch.

## Try it

```bash
cargo run --example absence
cargo test
```

## Pair with

- `sovereign_ledger` — the chain substrate this was designed to sit on
- `camazotz` — certified erasure (proof something *left*); tabula is proof it was *never there*
- `kola` — a second organism can witness the head a proof pins, so the history can't shrink later
