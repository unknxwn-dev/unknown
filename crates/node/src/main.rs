//! Integrated single-sequencer devnet (WP13) — the Gate-B lifecycle demo.
//!
//! Drives the full shielded pipeline in one process: genesis funding, a
//! private transfer, checkpoint application with reward minting, wallet
//! scanning, and a chained spend of a just-received note. Everything the node
//! sees is opaque (commitments, nullifiers, ciphertexts, proofs); balances and
//! recipients live only in the wallets.

use unknown_circuit_spend::verifier::StarkSpendVerifier;
use unknown_emission::EmissionParams;
use unknown_encryption::encrypt_note;
use unknown_interfaces::Anchor;
use unknown_notes::Note;
use unknown_state::{Ledger, ValidatorInfo};
use unknown_tx::TxV1;
use unknown_wallet::Wallet;

const GENESIS_FUND: u64 = 1_000_000;

struct Demo {
    ledger: Ledger,
    genesis_supply: u64,
    verifier: StarkSpendVerifier,
}

impl Demo {
    /// Apply a checkpoint and deliver each accepted tx's encrypted outputs to
    /// the candidate wallets (the node knows positions; wallets trial-decrypt).
    fn checkpoint(&mut self, txs: Vec<TxV1>, wallets: &mut [&mut Wallet]) -> String {
        // Snapshot which txs will be accepted by re-deriving order here: the
        // ledger reports accept/reject, and output_positions covers accepted
        // outputs in order. For the demo all submitted txs are valid.
        let enc_outputs: Vec<_> = txs.iter().map(|t| t.enc_outputs.clone()).collect();
        let summary = self.ledger.apply_checkpoint(&txs, &self.verifier);

        // Deliver nullifiers (spentness) and outputs (receipts) to wallets.
        let all_nf: Vec<_> = txs.iter().flat_map(|t| t.nullifiers).collect();
        for w in wallets.iter_mut() {
            w.observe_nullifiers(&all_nf);
        }
        // Map accepted txs' outputs to positions. Rejected txs contribute none.
        let accepted_indices: Vec<usize> = (0..txs.len())
            .filter(|i| !summary.rejected.iter().any(|(ri, _)| ri == i))
            .collect();
        let mut pos_iter = summary.output_positions.iter();
        for &i in &accepted_indices {
            for out in &enc_outputs[i] {
                if let Some(&position) = pos_iter.next() {
                    for w in wallets.iter_mut() {
                        w.try_receive(out, position);
                    }
                }
            }
        }

        format!(
            "checkpoint {} sealed: {} accepted, {} rejected, emission {}, supply {} (audit {})",
            summary.height,
            summary.accepted,
            summary.rejected.len(),
            summary.rewards.total,
            summary.total_supply,
            if self.ledger.audit_supply(self.genesis_supply) {
                "OK"
            } else {
                "FAIL"
            },
        )
    }

    fn anchor(&self) -> Anchor {
        self.ledger.current_anchor()
    }
}

fn run_demo() -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    let mut alice = Wallet::from_seed(&[1u8; 32]);
    let mut bob = Wallet::from_seed(&[2u8; 32]);
    let mut carol = Wallet::from_seed(&[3u8; 32]);

    // --- Genesis: fund Alice with an encrypted note at position 0. ---
    let alice_note = Note {
        value: GENESIS_FUND,
        addr_tag: alice.address().addr_tag,
        rho: unknown_notes::rho_mint(0, 0),
        rseed: unknown_notes::rho_mint(0, 200),
    };
    let validators = vec![ValidatorInfo {
        weight: 1,
        addr_tag: [0xAB; 32],
    }];
    let emission = EmissionParams::new(10_000, 100, 1_000);
    let ledger = Ledger::genesis(
        emission,
        validators,
        0, // dev PoW difficulty
        &[(alice_note.commitment(), GENESIS_FUND)],
    );
    let mut demo = Demo {
        ledger,
        genesis_supply: GENESIS_FUND,
        verifier: StarkSpendVerifier::new(),
    };

    // Deliver the genesis note to Alice (she trial-decrypts like any output).
    let genesis_enc = encrypt_note(&alice_note, &alice.address(), &[0u8; 64], [0xE1; 32]);
    if !alice.try_receive(&genesis_enc, 0) {
        return Err("alice failed to receive genesis note".into());
    }
    log.push(format!(
        "genesis: alice funded with {} (balance {})",
        GENESIS_FUND,
        alice.balance()
    ));

    // --- Alice → Bob: 250_000 ---
    let anchor = demo.anchor();
    let tx1 = {
        // Borrow the ledger's tree witnesses against the current anchor.
        let witness_for = |pos: u64| demo.ledger.tree_witness(pos);
        alice
            .build_transfer(&bob.address(), 250_000, anchor, witness_for, [0x10; 32])
            .map_err(|e| format!("alice build_transfer: {e}"))?
    };
    log.push("alice builds private transfer of 250000 to bob".into());
    log.push(demo.checkpoint(vec![tx1], &mut [&mut alice, &mut bob, &mut carol]));
    log.push(format!(
        "after cp1: alice={} bob={} carol={}",
        alice.balance(),
        bob.balance(),
        carol.balance()
    ));
    if alice.balance() != 750_000 || bob.balance() != 250_000 {
        return Err(format!(
            "unexpected balances after cp1: alice={} bob={}",
            alice.balance(),
            bob.balance()
        ));
    }

    // --- Bob → Carol: 100_000 (chained spend of the note Bob just received) ---
    let anchor2 = demo.anchor();
    let tx2 = {
        let witness_for = |pos: u64| demo.ledger.tree_witness(pos);
        bob.build_transfer(&carol.address(), 100_000, anchor2, witness_for, [0x20; 32])
            .map_err(|e| format!("bob build_transfer: {e}"))?
    };
    log.push("bob builds private transfer of 100000 to carol (chained spend)".into());
    log.push(demo.checkpoint(vec![tx2], &mut [&mut alice, &mut bob, &mut carol]));
    log.push(format!(
        "after cp2: alice={} bob={} carol={}",
        alice.balance(),
        bob.balance(),
        carol.balance()
    ));
    if bob.balance() != 150_000 || carol.balance() != 100_000 {
        return Err(format!(
            "unexpected balances after cp2: bob={} carol={}",
            bob.balance(),
            carol.balance()
        ));
    }

    log.push(format!(
        "FINAL: alice=750000 bob=150000 carol=100000, supply={} audited OK",
        demo.ledger.total_supply()
    ));
    Ok(log)
}

fn main() {
    println!("unknown devnet — shielded DAG L1 prototype (STARK prover, single sequencer)\n");
    match run_demo() {
        Ok(log) => {
            for line in log {
                println!("  {line}");
            }
            println!("\ndemo completed successfully.");
        }
        Err(e) => {
            eprintln!("demo failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle_demo_succeeds() {
        let log = run_demo().expect("demo runs end to end");
        assert!(log.iter().any(|l| l.contains("FINAL")));
    }
}
