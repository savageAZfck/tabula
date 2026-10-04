use tabula::{Chain, Identity, Tabula};

fn main() {
    let mut t = Tabula::new(Chain::new(), Identity::generate());
    t.record("met custodian at noon");
    t.record("approved tool dispatch 41");
    t.record("dream share from peer B");

    println!("history: {} committed entries", t.chain.len());

    // Certify a fact the history never contained.
    let proof = t.prove_absence("the stolen credential").unwrap();
    println!(
        "proof: {} entries scanned against head {}… — signed by {}…",
        proof.entries_scanned,
        &proof.head[..16],
        &proof.prover[..16]
    );
    println!("verified: {}", proof.check(&t.chain).unwrap());

    // And refuse to certify a lie.
    match t.prove_absence("approved tool dispatch 41") {
        Err(e) => println!("false proof refused: {e}"),
        Ok(_) => println!("ERROR: signed a false proof"),
    }
}
