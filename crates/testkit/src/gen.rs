//! Regenerate golden vectors: `cargo run -p unknown-testkit --bin gen-vectors`.
//! Paste the output into specs/vectors/core.md (reviewed change only).
fn main() {
    for (k, hexv) in unknown_testkit::vectors() {
        println!("{k} = {hexv}");
    }
}
