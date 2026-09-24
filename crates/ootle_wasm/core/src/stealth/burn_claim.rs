//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

//! Claiming a Layer 1 (minotari) burn.
//!
//! An L1 burn addressed to an Ootle account `P` is a stealth output: its on-chain claim key is
//! `C = s·G` with `s = H(p·R) + p` (`R` the burn's sender offset key, `p` the account secret). Only
//! `s` can seal the claim transaction, and the burn's ownership proof commits to `C`, so a client
//! building a `ClaimBurn` needs both of these.

use ootle_network::Network;
use tari_crypto::{keys::PublicKey, ristretto::RistrettoPublicKey, tari_utilities::ByteArray};
use tari_ootle_wallet_crypto::{StealthCryptoApi, kdfs::burn_claim_stealth_secret as crypto_burn_claim_stealth_secret};
use tari_template_lib_types::crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, SchnorrSignatureBytes};

use crate::{
    error::OotleWasmError,
    keys::{public_key_from_bytes, secret_key_from_bytes},
};

/// The stealth claim secret `s = H(p·R) + p` for an L1 burn, from the account secret `p` and the
/// burn's sender offset public key `R`. Seal the claim transaction with it.
pub fn burn_claim_stealth_secret(
    account_secret: &[u8],
    sender_offset_public_key: &[u8],
) -> Result<Vec<u8>, OotleWasmError> {
    let account_secret = secret_key_from_bytes(account_secret)?;
    let sender_offset_public_key = public_key_from_bytes(sender_offset_public_key)?;
    Ok(
        crypto_burn_claim_stealth_secret(&account_secret, &sender_offset_public_key)
            .as_bytes()
            .to_vec(),
    )
}

/// Checks an L1 burn's ownership proof the way a validator will, against the stealth claim key
/// derived from `stealth_secret`. A `false` here means the claim would be rejected — most often
/// because the burn was addressed to a different account.
pub fn validate_burn_claim_ownership_proof(
    network_byte: u8,
    ownership_nonce: &[u8],
    ownership_signature: &[u8],
    commitment: &[u8],
    value: u64,
    stealth_secret: &[u8],
) -> Result<bool, OotleWasmError> {
    let network = Network::try_from(network_byte).map_err(|e| OotleWasmError::InvalidNetwork(e.to_string()))?;
    let nonce = RistrettoPublicKeyBytes::from_bytes(ownership_nonce)
        .map_err(|_| byte_length("ownership proof nonce", 32, ownership_nonce.len()))?;
    let proof = SchnorrSignatureBytes::try_from_raw_parts(nonce.as_ref(), ownership_signature)
        .map_err(|_| byte_length("ownership proof signature", 32, ownership_signature.len()))?;
    let commitment =
        PedersenCommitmentBytes::from_bytes(commitment).map_err(|_| byte_length("commitment", 32, commitment.len()))?;
    let stealth_secret = secret_key_from_bytes(stealth_secret)?;
    let claimant = RistrettoPublicKey::from_secret_key(&stealth_secret);
    let claimant = RistrettoPublicKeyBytes::from_bytes(claimant.as_bytes())
        .map_err(|_| byte_length("stealth claim key", 32, claimant.as_bytes().len()))?;
    Ok(StealthCryptoApi::new().validate_burn_claim_ownership_proof(network, &proof, &commitment, value, &claimant))
}

fn byte_length(field: &'static str, expected: usize, got: usize) -> OotleWasmError {
    OotleWasmError::InvalidByteLength { field, expected, got }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::{encrypted_data::unblind_output, kdfs::encrypted_data_dh_kdf};

    /// A real burn built by the L1 wallet's WASM burn builder (`tari_l1_wasm::burn::build_burn`)
    /// for a known account secret. Checks the Ootle side reads it exactly as the L1 side wrote it.
    const FIXTURE: &str = include_str!("l1_burn_fixture.json");

    fn field<'a>(json: &'a serde_json::Value, key: &str) -> &'a str {
        json[key].as_str().unwrap_or_else(|| panic!("fixture missing {key}"))
    }

    #[test]
    fn l1_burn_fixture_is_claimable_by_its_account() {
        let json: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let account_secret = hex::decode(field(&json, "accountSecretHex")).unwrap();
        let sender_offset = hex::decode(field(&json, "senderOffsetPublicKeyHex")).unwrap();
        let commitment = hex::decode(field(&json, "commitmentHex")).unwrap();
        let amount = json["amount"].as_u64().unwrap();

        let s = burn_claim_stealth_secret(&account_secret, &sender_offset).unwrap();
        let claim_pk = RistrettoPublicKey::from_secret_key(&secret_key_from_bytes(&s).unwrap());
        assert_eq!(hex::encode(claim_pk.as_bytes()), field(&json, "stealthClaimPublicHex"));

        let valid = validate_burn_claim_ownership_proof(
            Network::Esmeralda.as_byte(),
            &hex::decode(field(&json, "ownershipNonceHex")).unwrap(),
            &hex::decode(field(&json, "ownershipSignatureHex")).unwrap(),
            &commitment,
            amount,
            &s,
        )
        .unwrap();
        assert!(
            valid,
            "ownership proof must verify against the derived stealth claim key"
        );

        // A different value must not verify: the proof binds the amount.
        let wrong_value = validate_burn_claim_ownership_proof(
            Network::Esmeralda.as_byte(),
            &hex::decode(field(&json, "ownershipNonceHex")).unwrap(),
            &hex::decode(field(&json, "ownershipSignatureHex")).unwrap(),
            &commitment,
            amount + 1,
            &s,
        )
        .unwrap();
        assert!(!wrong_value);

        // The value and mask decrypt with DH(p, R) and open the commitment.
        let key = encrypted_data_dh_kdf(&account_secret, &sender_offset).unwrap();
        let encrypted = hex::decode(field(&json, "encryptedDataHex")).unwrap();
        let decrypted = unblind_output(&commitment, &encrypted, &key, true).unwrap();
        assert_eq!(decrypted.value, amount);
    }

    #[test]
    fn a_different_account_cannot_claim() {
        let json: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let other = tari_crypto::ristretto::RistrettoSecretKey::random(&mut rand::rng());
        use tari_crypto::keys::SecretKey;
        let sender_offset = hex::decode(field(&json, "senderOffsetPublicKeyHex")).unwrap();
        let s = burn_claim_stealth_secret(other.as_bytes(), &sender_offset).unwrap();
        let valid = validate_burn_claim_ownership_proof(
            Network::Esmeralda.as_byte(),
            &hex::decode(field(&json, "ownershipNonceHex")).unwrap(),
            &hex::decode(field(&json, "ownershipSignatureHex")).unwrap(),
            &hex::decode(field(&json, "commitmentHex")).unwrap(),
            json["amount"].as_u64().unwrap(),
            &s,
        )
        .unwrap();
        assert!(!valid);
    }
}
