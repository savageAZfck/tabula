# Threat model — tabula

The chain hides the datum — every entry commits to all predecessors; a deleted entry breaks linkage. A proof is issued for a different history — the head and entry count are pinned into the signed body. A false proof is signed — prove_absence refuses KnowledgeFound before signing. The proof reveals the history — the chain stores sha256 commitments only. A stale proof is presented — the head pins a specific history; growth after proof time invalidates the check.

## What this crate guarantees

- prove_absence cannot emit a false proof — presence returns KnowledgeFound.
- Proofs pin query hash, chain head, and entry count into a signed body.
- Verification replays the scan over the actual chain — fully offline.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
