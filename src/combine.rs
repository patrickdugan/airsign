//! Online side, last step: put the signer's signatures into the PSBT the
//! watch-only wallet made, after checking each one against that PSBT's own
//! sighash. A mistyped word fails here and is traced back to its line.

use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Transaction, TxOut, Witness};

use crate::codec::{err, put_uleb, CodecError, LINE_BYTES};
use crate::request::xonly_of_p2tr;

fn spent_outputs(psbt: &Psbt) -> Result<Vec<TxOut>, CodecError> {
    psbt.unsigned_tx
        .input
        .iter()
        .zip(&psbt.inputs)
        .enumerate()
        .map(|(n, (txin, pin))| match (&pin.witness_utxo, &pin.non_witness_utxo) {
            (Some(w), _) => Ok(w.clone()),
            (None, Some(prev)) => prev
                .output
                .get(txin.previous_output.vout as usize)
                .cloned()
                .ok_or_else(|| CodecError(format!("input {n}: outpoint index out of range"))),
            _ => err(format!("input {n}: PSBT lacks the spent output")),
        })
        .collect()
}

/// Which transcript lines hold signature `k` (1-based, as printed).
pub fn lines_for_signature(k: usize, n_sigs: usize) -> (usize, usize) {
    let frame_len = 1 + 64 * n_sigs;
    let mut prefix = Vec::new();
    put_uleb(&mut prefix, frame_len as u64);
    let start = prefix.len() + 1 + 64 * k;
    let end = start + 63;
    (start / LINE_BYTES + 1, end / LINE_BYTES + 1)
}

pub fn combine(psbt: &mut Psbt, sigs: &[schnorr::Signature]) -> Result<Transaction, CodecError> {
    let n = psbt.unsigned_tx.input.len();
    if sigs.len() != n {
        return err(format!("got {} signatures for a transaction with {n} inputs", sigs.len()));
    }
    let prevouts = spent_outputs(psbt)?;
    let secp = Secp256k1::verification_only();
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let all = Prevouts::All(&prevouts);
    for (k, sig) in sigs.iter().enumerate() {
        let key = xonly_of_p2tr(&prevouts[k].script_pubkey)
            .ok_or_else(|| CodecError(format!("input {k} is not a taproot output")))?;
        let sighash = cache
            .taproot_key_spend_signature_hash(k, &all, TapSighashType::Default)
            .map_err(|e| CodecError(format!("sighash for input {k}: {e}")))?;
        let msg = Message::from_digest(sighash.to_byte_array());
        if secp.verify_schnorr(sig, &msg, &key).is_err() {
            let (a, b) = lines_for_signature(k, n);
            let where_ = if a == b { format!("line {a}") } else { format!("lines {a}-{b}") };
            return err(format!(
                "signature {k} does not verify. If you typed the words, recheck {where_}; \
                 otherwise the signer signed a different transaction (wrong request, or tampering)"
            ));
        }
    }
    for (pin, sig) in psbt.inputs.iter_mut().zip(sigs) {
        pin.final_script_witness = Some(Witness::from_slice(&[sig.as_ref()]));
        pin.tap_key_sig = None;
        pin.tap_script_sigs.clear();
        pin.tap_scripts.clear();
        pin.tap_key_origins.clear();
        pin.tap_internal_key = None;
        pin.tap_merkle_root = None;
        pin.partial_sigs.clear();
        pin.sighash_type = None;
        pin.bip32_derivation.clear();
        pin.redeem_script = None;
        pin.witness_script = None;
    }
    Ok(psbt.clone().extract_tx_unchecked_fee_rate())
}
