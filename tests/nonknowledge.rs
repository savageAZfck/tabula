use tabula::{Chain, Error, Identity, Tabula};

fn prover_with(entries: &[&str]) -> Tabula {
    let mut t = Tabula::new(Chain::new(), Identity::generate());
    for e in entries {
        t.record(e);
    }
    t
}

#[test]
fn absence_proves_and_verifies() {
    let t = prover_with(&["fact one", "fact two", "fact three"]);
    let proof = t.prove_absence("never seen this").unwrap();
    assert!(proof.verified);
    assert_eq!(proof.entries_scanned, 3);
    assert!(proof.check(&t.chain).unwrap());
}

#[test]
fn refuses_to_sign_false_proof() {
    let t = prover_with(&["secret I actually know"]);
    match t.prove_absence("secret I actually know") {
        Err(Error::KnowledgeFound { seq }) => assert_eq!(seq, 0),
        _ => panic!("should have refused"),
    }
}

#[test]
fn proof_rejects_chain_where_content_present() {
    let t = prover_with(&["a", "b"]);
    let proof = t.prove_absence("c").unwrap();
    // A different chain containing "c" must fail the check.
    let mut other = Chain::new();
    other.append(b"c");
    assert!(proof.check(&other).is_err());
}

#[test]
fn proof_rejects_tampered_chain() {
    let t = prover_with(&["x", "y", "z"]);
    let proof = t.prove_absence("q").unwrap();
    let mut forged = t.chain.clone();
    forged.entries[1].content_hash = Chain::content_commitment(b"q");
    assert!(proof.check(&forged).is_err());
}

#[test]
fn proof_rejects_extended_chain() {
    let t = prover_with(&["x"]);
    let proof = t.prove_absence("q").unwrap();
    let mut extended = t.chain.clone();
    extended.append(b"q");
    assert!(proof.check(&extended).is_err());
}

#[test]
fn empty_chain_certifies_absence() {
    let t = Tabula::new(Chain::new(), Identity::generate());
    let proof = t.prove_absence("anything").unwrap();
    assert_eq!(proof.entries_scanned, 0);
    assert!(proof.check(&t.chain).unwrap());
}

#[test]
fn signature_is_over_body() {
    let t = prover_with(&["a"]);
    let mut proof = t.prove_absence("b").unwrap();
    proof.ts += 1; // tamper signed field
    assert!(proof.check(&t.chain).is_err());
}

#[test]
fn commitments_hide_content() {
    let mut chain = Chain::new();
    chain.append(b"the raw secret");
    let raw = serde_json::to_string(&chain).unwrap();
    assert!(!raw.contains("the raw secret"));
    assert!(raw.contains(&Chain::content_commitment(b"the raw secret")));
}
