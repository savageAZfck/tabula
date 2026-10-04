//! # tabula — proof of non-knowledge.
//!
//! Certified *absence*: the organism attests that a given datum (identified
//! by content hash) **never appeared** in its append-only, hash-chained
//! history — without revealing the history itself.
//!
//! ## Why this is hard — and why it works here
//!
//! Ordinary logs can't prove a negative: delete the row, delete the
//! evidence. But a hash-chained ledger is different — every entry commits
//! to all previous entries. So tabula runs a **committed scan**:
//!
//! 1. The prover walks the whole chain, checks each entry's content
//!    commitment against the query hash, and recomputes the chain.
//! 2. It signs a `NonKnowledgeProof` covering: the query hash, the chain
//!    head, the entry count, and the scan timestamp.
//! 3. Any verifier with the chain can replay the scan identically — the
//!    chain can't be edited to hide a hit without breaking its hashes.
//!
//! The proof is only as strong as the chain's integrity — which is
//! exactly what sovereign_ledger already guarantees.
//!
//! ## What it can and can't prove
//!
//! - ✅ "this content-hash never occurred in my history" — checkable.
//! - ❌ "I don't know this fact" — unknowable for any mind; tabula
//!   certifies absence from *history*, not absence from a brain.
//!
//! ```rust
//! use tabula::{Chain, Identity, Tabula};
//! let chain = Chain::new();
//! let mut t = Tabula::new(chain, Identity::generate());
//! t.record("hello world");
//! let proof = t.prove_absence("content-that-was-never-seen").unwrap();
//! assert!(proof.verified);
//! assert!(proof.check(&t.chain).unwrap());
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

// ── errors ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Error {
    /// The queried content hash IS present in the chain — the requested
    /// non-knowledge proof is false and cannot be signed.
    KnowledgeFound {
        seq: u64,
    },
    /// Chain integrity failure — the proof's foundation is broken.
    BrokenChain(String),
    /// A signature or proof failed verification.
    BadProof(String),
    Serialization(String),
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KnowledgeFound { seq } => {
                write!(f, "content found at seq {seq} — cannot prove absence")
            }
            Error::BrokenChain(m) => write!(f, "chain integrity failure: {m}"),
            Error::BadProof(m) => write!(f, "proof verification failed: {m}"),
            Error::Serialization(m) => write!(f, "serialization: {m}"),
            Error::Io(m) => write!(f, "io: {m}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn canonical<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}
mod hex {
    pub fn encode(b: impl AsRef<[u8]>) -> String {
        b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

// ── identity ───────────────────────────────────────────────────────

/// Ed25519 identity signing non-knowledge proofs.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Identity {
            signing: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Identity {
            signing: SigningKey::from_bytes(bytes),
        }
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }
    /// Raw 32-byte signing seed — for key-file persistence.
    pub fn seed(&self) -> &[u8; 32] {
        self.signing.as_bytes()
    }
    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.signing.sign(msg).to_bytes())
    }
}

// ── the chain ──────────────────────────────────────────────────────

/// One append-only, hash-chained record. Each entry commits to a
/// content hash — the only thing absence proofs ever inspect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub content_hash: String,
    pub prev_hash: String,
    pub hash: String,
    pub ts: u64,
}

/// An append-only hash-chained history — the minimal substrate a
/// non-knowledge proof needs. Content is stored as a *commitment*
/// (sha256), so the chain itself reveals nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Chain {
    pub entries: Vec<Entry>,
}

impl Chain {
    pub fn new() -> Self {
        Chain::default()
    }

    /// Append a content commitment derived from the raw payload.
    pub fn append(&mut self, content: &[u8]) -> Entry {
        self.append_commitment(&sha256_hex(content))
    }

    /// Append a pre-computed content commitment.
    pub fn append_commitment(&mut self, content_hash: &str) -> Entry {
        let seq = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "genesis".into());
        let ts = now_secs();
        let hash = sha256_hex(&canonical(&serde_json::json!({
            "seq": seq, "content_hash": content_hash,
            "prev_hash": prev_hash, "ts": ts,
        })));
        let entry = Entry {
            seq,
            content_hash: content_hash.to_string(),
            prev_hash,
            hash,
            ts,
        };
        self.entries.push(entry.clone());
        entry
    }

    /// Verify linkage end to end. Returns the first broken seq on failure.
    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "genesis".to_string();
        for e in &self.entries {
            if e.prev_hash != prev {
                return Err(Error::BrokenChain(format!("seq {} link broken", e.seq)));
            }
            let expect = sha256_hex(&canonical(&serde_json::json!({
                "seq": e.seq, "content_hash": e.content_hash,
                "prev_hash": e.prev_hash, "ts": e.ts,
            })));
            if e.hash != expect {
                return Err(Error::BrokenChain(format!("seq {} hash mismatch", e.seq)));
            }
            prev = e.hash.clone();
        }
        Ok(())
    }

    pub fn head(&self) -> String {
        self.entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "genesis".into())
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Commitment for arbitrary content — same function proofs use.
    pub fn content_commitment(content: &[u8]) -> String {
        sha256_hex(content)
    }
}

// ── the proof ──────────────────────────────────────────────────────

/// A signed certificate that `query_hash` never occurred among the
/// `head`-committed history of `prover`. Replayable by anyone holding
/// the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonKnowledgeProof {
    /// sha256 of the query content (never the content itself).
    pub query_hash: String,
    /// Prover's public key.
    pub prover: String,
    /// Chain head at proof time — pins the scan to a specific history.
    pub head: String,
    /// Entries scanned — must match the chain at `head`.
    pub entries_scanned: u64,
    /// Scan timestamp.
    pub ts: u64,
    /// ed25519 signature over the proof body.
    pub signature: String,
    /// Convenience flag set at proof creation; `check()` recomputes.
    pub verified: bool,
}

impl NonKnowledgeProof {
    fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "query_hash": self.query_hash,
            "prover": self.prover,
            "head": self.head,
            "entries_scanned": self.entries_scanned,
            "ts": self.ts,
        })
    }

    /// Independent re-verification against a chain: integrity, head
    /// pinning, entry count, absence, signature.
    pub fn check(&self, chain: &Chain) -> Result<bool, Error> {
        chain.verify()?;
        if chain.head() != self.head {
            return Err(Error::BadProof("proof head does not match chain".into()));
        }
        if chain.len() as u64 != self.entries_scanned {
            return Err(Error::BadProof("entry count mismatch".into()));
        }
        if chain
            .entries
            .iter()
            .any(|e| e.content_hash == self.query_hash)
        {
            return Err(Error::BadProof("query content IS present".into()));
        }
        let pk = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(
                hex::decode(&self.prover).map_err(|_| Error::BadProof("bad prover key".into()))?,
            )
            .map_err(|_| Error::BadProof("bad prover key".into()))?,
        )
        .map_err(|_| Error::BadProof("bad prover key".into()))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|_| Error::BadProof("bad signature".into()))?;
        let sig = Signature::from_bytes(
            &<[u8; 64]>::try_from(sig_bytes.as_slice())
                .map_err(|_| Error::BadProof("bad signature".into()))?,
        );
        pk.verify(&canonical(&self.body()), &sig)
            .map_err(|_| Error::BadProof("signature invalid".into()))?;
        Ok(true)
    }
}

// ── the prover ─────────────────────────────────────────────────────

/// The organism-side prover: records history, signs absence.
pub struct Tabula {
    pub chain: Chain,
    pub identity: Identity,
}

impl Tabula {
    pub fn new(chain: Chain, identity: Identity) -> Self {
        Tabula { chain, identity }
    }

    /// Record content into the chain (as a commitment).
    pub fn record(&mut self, content: &str) -> Entry {
        self.chain.append(content.as_bytes())
    }

    /// Attempt to certify that `content` never occurred. Returns
    /// `KnowledgeFound` — refusing to sign a false proof — if it did.
    pub fn prove_absence(&self, content: &str) -> Result<NonKnowledgeProof, Error> {
        self.prove_absence_hash(&Chain::content_commitment(content.as_bytes()))
    }

    /// Same, when only the commitment is known.
    pub fn prove_absence_hash(&self, query_hash: &str) -> Result<NonKnowledgeProof, Error> {
        self.chain.verify()?;
        if let Some(hit) = self
            .chain
            .entries
            .iter()
            .find(|e| e.content_hash == query_hash)
        {
            return Err(Error::KnowledgeFound { seq: hit.seq });
        }
        let mut proof = NonKnowledgeProof {
            query_hash: query_hash.to_string(),
            prover: self.identity.public_key(),
            head: self.chain.head(),
            entries_scanned: self.chain.len() as u64,
            ts: now_secs(),
            signature: String::new(),
            verified: true,
        };
        proof.signature = self.identity.sign(&canonical(&proof.body()));
        Ok(proof)
    }
}
