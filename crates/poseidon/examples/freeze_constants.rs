//! Regenerate `specs/vectors/poseidon2.json` from the seed generator of record.
//!
//! Run from the repo root:
//!
//! ```text
//! cargo run -p unknown-poseidon --example freeze_constants > specs/vectors/poseidon2.json
//! ```
//!
//! The library test `frozen_constants_match_generator` asserts the committed
//! file still equals what this prints, so the spec can never silently drift.

use unknown_poseidon::{derive_from_seed, ConstantsSpec};

fn main() {
    let spec = ConstantsSpec::from_constants(&derive_from_seed());
    println!("{}", serde_json::to_string_pretty(&spec).unwrap());
}
