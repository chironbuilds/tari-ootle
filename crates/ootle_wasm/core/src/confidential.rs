//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

//! Building a `ConfidentialWithdrawProof` client-side, for calling the Account template's
//! `withdraw_confidential`/`join_confidential` methods -- the vault-based privacy mechanism
//! ("Confidential" `ResourceType`), distinct from the stealth (`Stealth` `ResourceType`) module
//! alongside this one.
//!
//! Unlike stealth, this crate does NOT expose a JS-side CBOR encoder for the result: the proof is
//! `tari_bor`-encoded here, in Rust, using the same derive-generated `Encode` impl the chain itself
//! decodes with (`ConfidentialWithdrawProof` derives `minicbor::Encode` in
//! `tari_template_lib_types::confidential`). A caller wraps the returned bytes directly as an
//! instruction `Literal` arg (hex-encoded, matching the convention every other `*Literal` helper in
//! the TS SDK already uses) -- no bespoke struct encoder to write or get subtly wrong on the JS side.

use tari_crypto::{ristretto::RistrettoSecretKey, tari_utilities::ByteArray};
use tari_ootle_wallet_crypto::{MaskAndValue, confidential::create_withdraw_proof};
use tari_template_lib_types::Amount;

use crate::{
    error::OotleWasmError,
    stealth::{InputWitness, OutputWitnessJson},
};

/// Local copy of `stealth::types::decode_secret_key` -- that helper is `pub(crate)` but its parent
/// `types` module is private to `stealth`, so it isn't reachable from a sibling module. Small enough
/// not to be worth loosening stealth's module privacy for.
fn decode_secret_key(hex_str: &str, field: &'static str) -> Result<RistrettoSecretKey, OotleWasmError> {
    if hex_str.len() != 64 {
        return Err(OotleWasmError::InvalidByteLength {
            field,
            expected: 32,
            got: hex_str.len() / 2,
        });
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut bytes)?;
    RistrettoSecretKey::from_canonical_bytes(&bytes).map_err(|e| OotleWasmError::InvalidSecretKey(e.to_string()))
}

/// Builds a `ConfidentialWithdrawProof` and returns its `tari_bor`-encoded bytes, ready to wrap as
/// an instruction `Literal` arg.
///
/// `inputs_json` is a JSON array of [`InputWitness`] (`{value, mask}`) for each confidential UTXO
/// being spent -- pass `"[]"` for a revealed-only withdrawal (deposit into the vault). `output_json`
/// / `change_json` are each an optional [`OutputWitnessJson`] (`null`/absent to skip that side) --
/// set `output_json` to withdraw into a new confidential output, leave it absent for a fully
/// revealed withdrawal. `*_revealed_amount` fields are the plaintext (publicly visible) portion on
/// each side; a call can mix confidential and revealed amounts on either side, per
/// `ConfidentialWithdrawProof`'s own doc comment.
pub fn create_confidential_withdraw_proof_literal(
    inputs_json: &str,
    input_revealed_amount: u64,
    output_json: Option<&str>,
    output_revealed_amount: u64,
    change_json: Option<&str>,
    change_revealed_amount: u64,
) -> Result<Vec<u8>, OotleWasmError> {
    let inputs: Vec<InputWitness> = serde_json::from_str(inputs_json)?;
    let mask_and_values = inputs
        .into_iter()
        .map(|iw| -> Result<MaskAndValue, OotleWasmError> {
            let mask = decode_secret_key(&iw.mask, "mask")?;
            Ok(MaskAndValue::new(iw.value, mask))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let output = parse_output_witness(output_json)?;
    let change = parse_output_witness(change_json)?;

    let proof = create_withdraw_proof(
        &mask_and_values,
        Amount::from_u64(input_revealed_amount),
        output.as_ref(),
        Amount::from_u64(output_revealed_amount),
        change.as_ref(),
        Amount::from_u64(change_revealed_amount),
    )
    .map_err(|e| OotleWasmError::Confidential(e.to_string()))?;

    Ok(tari_bor::encode(&proof)?)
}

fn parse_output_witness(json: Option<&str>) -> Result<Option<tari_ootle_wallet_crypto::OutputWitness>, OotleWasmError> {
    json.map(|s| -> Result<_, OotleWasmError> {
        let dto: OutputWitnessJson = serde_json::from_str(s)?;
        dto.try_into_witness()
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use tari_crypto::{keys::SecretKey, ristretto::RistrettoSecretKey, tari_utilities::ByteArray};
    use tari_template_lib_types::{EncryptedData, confidential::ConfidentialWithdrawProof};

    use super::*;

    fn output_witness_json(amount: u64) -> String {
        let mask = RistrettoSecretKey::random(&mut rand::rng());
        format!(
            r#"{{"amount":{amount},"mask":"{}","sender_public_nonce":"{}","encrypted_data":{}}}"#,
            hex::encode(mask.as_bytes()),
            "00".repeat(32),
            serde_json::to_string(&EncryptedData::try_from(vec![0; EncryptedData::min_size()]).unwrap()).unwrap(),
        )
    }

    #[test]
    fn round_trips_a_revealed_only_output() {
        let output = output_witness_json(500);
        let bytes = create_confidential_withdraw_proof_literal("[]", 500, Some(&output), 0, None, 0).unwrap();
        assert!(!bytes.is_empty());
        // Decodes back into exactly the type the engine expects for this instruction arg -- the
        // whole point of encoding here instead of leaving it to a hand-written JS encoder.
        let decoded: ConfidentialWithdrawProof = tari_bor::decode(&bytes).unwrap();
        assert_eq!(decoded.inputs.len(), 0);
        assert_eq!(decoded.input_revealed_amount, Amount::from_u64(500));
    }

    #[test]
    fn round_trips_with_a_spent_input() {
        let mask = RistrettoSecretKey::random(&mut rand::rng());
        let inputs = format!(r#"[{{"value":1000,"mask":"{}"}}]"#, hex::encode(mask.as_bytes()));
        let output = output_witness_json(600);
        let change = output_witness_json(400);
        let bytes = create_confidential_withdraw_proof_literal(&inputs, 0, Some(&output), 0, Some(&change), 0).unwrap();
        let decoded: ConfidentialWithdrawProof = tari_bor::decode(&bytes).unwrap();
        assert_eq!(decoded.inputs.len(), 1);
    }

    #[test]
    fn rejects_malformed_input_json() {
        create_confidential_withdraw_proof_literal("not json", 0, None, 0, None, 0).unwrap_err();
    }
}
