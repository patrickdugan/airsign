//! SIGN_REQUEST: the smallest description of a single-key BIP86 taproot spend
//! from which the signer can rebuild the exact transaction and every value the
//! BIP341 sighash commits to.
//!
//! The signer is never sent a script for its own coins. Inputs and own outputs
//! are sent as derivation paths and the signer derives the scripts itself, so
//! "change" cannot point anywhere the signer did not derive.
//!
//! body := flags(1) fp(4) account version locktime [sequence]
//!         n_in  { txid(32) vout amount path }*
//!         n_out { kind(1) payload amount }*
//! (all integers LEB128; path = index*2 + change)
//! flags: bits 0-1 network, bits 2-3 sequence mode, bits 4-7 zero.
//! output kinds: 0 own(path) 1 p2tr(32) 2 p2wpkh(20) 3 p2wsh(32) 4 p2pkh(20)
//!               5 p2sh(20) 6 raw(len, bytes)

use std::collections::HashSet;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Network, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid};

use crate::codec::{err, put_uleb, CodecError, Reader};
use crate::frame::{coin_type, expect, net_code, net_from_code, seal, Kind};

pub const MAX_INPUTS: usize = 250;
pub const MAX_OUTPUTS: usize = 250;
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
const MAX_RAW_SCRIPT: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyPath {
    pub change: bool,
    pub index: u32,
}

impl KeyPath {
    fn code(self) -> u64 {
        (self.index as u64) << 1 | self.change as u64
    }

    fn from_code(c: u64) -> Result<Self, CodecError> {
        let index = c >> 1;
        if index >= 1 << 31 {
            return err("address index out of range");
        }
        Ok(KeyPath { change: c & 1 == 1, index: index as u32 })
    }

    pub fn describe(self, network: Network, account: u32) -> String {
        format!("m/86h/{}h/{}h/{}/{}", coin_type(network), account, self.change as u8, self.index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReqInput {
    pub outpoint: OutPoint,
    pub amount: u64,
    pub path: KeyPath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dest {
    Own(KeyPath),
    Script(ScriptBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReqOutput {
    pub dest: Dest,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub network: Network,
    pub master_fp: Fingerprint,
    pub account: u32,
    pub version: u32,
    pub lock_time: u32,
    pub sequence: u32,
    pub inputs: Vec<ReqInput>,
    pub outputs: Vec<ReqOutput>,
}

fn script_template(s: &ScriptBuf) -> (u8, &[u8]) {
    let b = s.as_bytes();
    if s.is_p2tr() {
        (1, &b[2..34])
    } else if s.is_p2wpkh() {
        (2, &b[2..22])
    } else if s.is_p2wsh() {
        (3, &b[2..34])
    } else if s.is_p2pkh() {
        (4, &b[3..23])
    } else if s.is_p2sh() {
        (5, &b[2..22])
    } else {
        (6, b)
    }
}

fn script_from_template(kind: u8, r: &mut Reader) -> Result<ScriptBuf, CodecError> {
    let v = match kind {
        1 => [&[0x51, 0x20][..], r.bytes(32)?].concat(),
        2 => [&[0x00, 0x14][..], r.bytes(20)?].concat(),
        3 => [&[0x00, 0x20][..], r.bytes(32)?].concat(),
        4 => [&[0x76, 0xa9, 0x14][..], r.bytes(20)?, &[0x88, 0xac][..]].concat(),
        5 => [&[0xa9, 0x14][..], r.bytes(20)?, &[0x87][..]].concat(),
        6 => {
            let n = r.uleb()? as usize;
            if n > MAX_RAW_SCRIPT {
                return err("output script too long");
            }
            r.bytes(n)?.to_vec()
        }
        k => return err(format!("unknown output kind {k}")),
    };
    Ok(ScriptBuf::from_bytes(v))
}

/// Check every available source for the spent output. A PSBT may carry both
/// witness_utxo and non_witness_utxo; accepting inconsistent copies would let
/// the coordinator give different amounts or scripts to different components.
pub fn spent_output_from_psbt(
    txin: &TxIn,
    pin: &bitcoin::psbt::Input,
    n: usize,
) -> Result<TxOut, CodecError> {
    let prevout = match &pin.non_witness_utxo {
        Some(prev) => {
            if prev.compute_txid() != txin.previous_output.txid {
                return err(format!("input {n}: non_witness_utxo txid does not match outpoint"));
            }
            Some(prev.output.get(txin.previous_output.vout as usize)
                .cloned()
                .ok_or_else(|| CodecError(format!("input {n}: non_witness_utxo vout is out of range")))?)
        }
        None => None,
    };
    match (&pin.witness_utxo, prevout) {
        (Some(witness), Some(full)) if *witness != full => {
            err(format!("input {n}: witness_utxo disagrees with non_witness_utxo"))
        }
        (Some(witness), _) => Ok(witness.clone()),
        (None, Some(full)) => Ok(full),
        (None, None) => err(format!("input {n}: PSBT lacks the spent output")),
    }
}

impl SignRequest {
    pub fn encode(&self) -> Vec<u8> {
        let seq_mode: u8 = match self.sequence {
            0xffff_fffd => 0,
            0xffff_ffff => 1,
            0xffff_fffe => 2,
            _ => 3,
        };
        let mut b = Vec::with_capacity(64 + 48 * self.inputs.len() + 40 * self.outputs.len());
        b.push(net_code(self.network) | seq_mode << 2);
        b.extend_from_slice(self.master_fp.as_bytes());
        put_uleb(&mut b, self.account as u64);
        put_uleb(&mut b, self.version as u64);
        put_uleb(&mut b, self.lock_time as u64);
        if seq_mode == 3 {
            put_uleb(&mut b, self.sequence as u64);
        }
        put_uleb(&mut b, self.inputs.len() as u64);
        for i in &self.inputs {
            b.extend_from_slice(&i.outpoint.txid.to_byte_array());
            put_uleb(&mut b, i.outpoint.vout as u64);
            put_uleb(&mut b, i.amount);
            put_uleb(&mut b, i.path.code());
        }
        put_uleb(&mut b, self.outputs.len() as u64);
        for o in &self.outputs {
            match &o.dest {
                Dest::Own(p) => {
                    b.push(0);
                    put_uleb(&mut b, p.code());
                }
                Dest::Script(s) => {
                    let (kind, payload) = script_template(s);
                    b.push(kind);
                    if kind == 6 {
                        put_uleb(&mut b, payload.len() as u64);
                    }
                    b.extend_from_slice(payload);
                }
            }
            put_uleb(&mut b, o.amount);
        }
        seal(Kind::Request, &b)
    }

    pub fn decode(frame: &[u8]) -> Result<Self, CodecError> {
        let body = expect(frame, Kind::Request)?;
        let mut r = Reader::new(body);
        let flags = r.u8()?;
        if flags & 0xf0 != 0 {
            return err("request uses flags this build does not understand");
        }
        let master_fp = Fingerprint::from(r.array::<4>()?);
        let account = r.uleb_u32("account")?;
        if account >= 1 << 31 {
            return err("account index out of range");
        }
        let version = r.uleb_u32("transaction version")?;
        let lock_time = r.uleb_u32("locktime")?;
        let sequence = match (flags >> 2) & 3 {
            0 => 0xffff_fffd,
            1 => 0xffff_ffff,
            2 => 0xffff_fffe,
            _ => r.uleb_u32("sequence")?,
        };
        let n_in = r.uleb()? as usize;
        if n_in == 0 || n_in > MAX_INPUTS {
            return err(format!("request must have 1 to {MAX_INPUTS} inputs"));
        }
        let mut inputs = Vec::with_capacity(n_in);
        let mut seen = HashSet::new();
        for _ in 0..n_in {
            let txid = Txid::from_byte_array(r.array::<32>()?);
            let vout = r.uleb_u32("output index")?;
            let amount = r.uleb()?;
            if amount > MAX_MONEY {
                return err("input amount exceeds 21 million BTC");
            }
            let path = KeyPath::from_code(r.uleb()?)?;
            let outpoint = OutPoint { txid, vout };
            if !seen.insert(outpoint) {
                return err("the same coin is spent twice");
            }
            inputs.push(ReqInput { outpoint, amount, path });
        }
        let n_out = r.uleb()? as usize;
        if n_out == 0 || n_out > MAX_OUTPUTS {
            return err(format!("request must have 1 to {MAX_OUTPUTS} outputs"));
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let kind = r.u8()?;
            let dest = if kind == 0 {
                Dest::Own(KeyPath::from_code(r.uleb()?)?)
            } else {
                Dest::Script(script_from_template(kind, &mut r)?)
            };
            let amount = r.uleb()?;
            if amount > MAX_MONEY {
                return err("output amount exceeds 21 million BTC");
            }
            outputs.push(ReqOutput { dest, amount });
        }
        r.finish()?;
        Ok(SignRequest {
            network: net_from_code(flags),
            master_fp,
            account,
            version,
            lock_time,
            sequence,
            inputs,
            outputs,
        })
    }

    pub fn total_in(&self) -> u64 {
        self.inputs.iter().map(|i| i.amount).sum()
    }

    pub fn total_out(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    /// Build a request from a PSBT made by a watch-only wallet (Bitcoin Core,
    /// Sparrow, ...). Every input must be a BIP86 key-path spend from one
    /// account; outputs whose BIP32 origin and script check out become `Own`.
    pub fn from_psbt<C: Verification>(
        secp: &Secp256k1<C>,
        psbt: &Psbt,
        network: Network,
    ) -> Result<Self, CodecError> {
        let tx = &psbt.unsigned_tx;
        let coin = coin_type(network);
        if tx.input.is_empty() || tx.output.is_empty() {
            return err("PSBT has no inputs or no outputs");
        }
        let sequence = tx.input[0].sequence.0;
        if tx.input.iter().any(|i| i.sequence != Sequence(sequence)) {
            return err("inputs use different nSequence values; airsign v1 needs them equal");
        }
        let mut account: Option<(Fingerprint, u32)> = None;
        let mut inputs = Vec::new();
        for (n, (txin, pin)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
            let utxo = spent_output_from_psbt(txin, pin, n)?;
            if !utxo.script_pubkey.is_p2tr() {
                return err(format!("input {n}: not a taproot output; airsign v1 signs BIP86 single-key taproot only"));
            }
            let mut found = None;
            for (xonly, (leaves, (fp, path))) in &pin.tap_key_origins {
                if !leaves.is_empty() {
                    continue;
                }
                if let Some((acct, kp)) = parse_bip86_path(path, coin) {
                    if ScriptBuf::new_p2tr(secp, *xonly, None) == utxo.script_pubkey {
                        found = Some((*fp, acct, kp));
                    }
                }
            }
            let (fp, acct, kp) = found.ok_or_else(|| {
                CodecError(format!(
                    "input {n}: no BIP86 key origin (m/86h/{coin}h/acct'/c/i) that matches the spent script; \
                     is this wallet a single-key taproot descriptor with key origins?"
                ))
            })?;
            match account {
                None => account = Some((fp, acct)),
                Some(a) if a != (fp, acct) => {
                    return err(format!("input {n}: belongs to a different wallet or account than input 0"))
                }
                _ => {}
            }
            inputs.push(ReqInput { outpoint: txin.previous_output, amount: utxo.value.to_sat(), path: kp });
        }
        let (master_fp, account) = account.expect("at least one input");
        let mut outputs = Vec::new();
        for (txout, pout) in tx.output.iter().zip(&psbt.outputs) {
            let mut dest = Dest::Script(txout.script_pubkey.clone());
            for (xonly, (leaves, (fp, path))) in &pout.tap_key_origins {
                if !leaves.is_empty() || *fp != master_fp {
                    continue;
                }
                if let Some((acct, kp)) = parse_bip86_path(path, coin) {
                    if acct == account && ScriptBuf::new_p2tr(secp, *xonly, None) == txout.script_pubkey {
                        dest = Dest::Own(kp);
                    }
                }
            }
            outputs.push(ReqOutput { dest, amount: txout.value.to_sat() });
        }
        Ok(SignRequest {
            network,
            master_fp,
            account,
            version: tx.version.0 as u32,
            lock_time: tx.lock_time.to_consensus_u32(),
            sequence,
            inputs,
            outputs,
        })
    }
}

/// m/86'/coin'/account'/change/index -> (account, path)
pub fn parse_bip86_path(path: &DerivationPath, coin: u32) -> Option<(u32, KeyPath)> {
    let p: Vec<ChildNumber> = path.into_iter().copied().collect();
    if p.len() != 5 {
        return None;
    }
    let hard = |c: ChildNumber| match c {
        ChildNumber::Hardened { index } => Some(index),
        _ => None,
    };
    let soft = |c: ChildNumber| match c {
        ChildNumber::Normal { index } => Some(index),
        _ => None,
    };
    if hard(p[0])? != 86 || hard(p[1])? != coin {
        return None;
    }
    let account = hard(p[2])?;
    let change = soft(p[3])?;
    if change > 1 {
        return None;
    }
    Some((account, KeyPath { change: change == 1, index: soft(p[4])? }))
}

pub fn xonly_of_p2tr(spk: &ScriptBuf) -> Option<XOnlyPublicKey> {
    if !spk.is_p2tr() {
        return None;
    }
    XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample() -> SignRequest {
        SignRequest {
            network: Network::Bitcoin,
            master_fp: Fingerprint::from([0x73, 0xc5, 0xda, 0x0a]),
            account: 0,
            version: 2,
            lock_time: 917_342,
            sequence: 0xffff_fffd,
            inputs: vec![ReqInput {
                outpoint: OutPoint::from_str(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:1",
                )
                .unwrap(),
                amount: 1_234_567,
                path: KeyPath { change: false, index: 4 },
            }],
            outputs: vec![
                ReqOutput {
                    dest: Dest::Script(
                        ScriptBuf::from_hex("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
                            .unwrap(),
                    ),
                    amount: 1_000_000,
                },
                ReqOutput { dest: Dest::Own(KeyPath { change: true, index: 7 }), amount: 233_000 },
            ],
        }
    }

    #[test]
    fn roundtrip_and_size() {
        let r = sample();
        let f = r.encode();
        assert_eq!(SignRequest::decode(&f).unwrap(), r);
        // 1-in / 2-out taproot spend with change: 95 bytes framed.
        assert_eq!(f.len(), 95);
    }

    #[test]
    fn every_script_template_roundtrips() {
        let mut r = sample();
        for hex in [
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            "a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1887",
            "6a0b68656c6c6f20776f726c64",
            "",
        ] {
            r.outputs[0].dest = Dest::Script(ScriptBuf::from_hex(hex).unwrap());
            r.sequence = 0x1234;
            assert_eq!(SignRequest::decode(&r.encode()).unwrap(), r, "{hex}");
        }
    }

    #[test]
    fn rejects_duplicate_inputs_and_trailing_bytes() {
        let mut r = sample();
        r.inputs.push(r.inputs[0].clone());
        assert!(SignRequest::decode(&r.encode()).is_err());
        let r = sample();
        let mut f = r.encode();
        let n = f.len();
        f.truncate(n - 4);
        f.push(0);
        let c = crate::codec::crc32(&f);
        f.extend_from_slice(&c.to_be_bytes());
        assert!(SignRequest::decode(&f).is_err());
    }
}

#[cfg(test)]
mod signer_pipeline_regressions {
    use super::*;
    use bitcoin::bip32::DerivationPath;
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, Sequence, Transaction, TxIn, Witness};
    use std::str::FromStr;

    /// A synthetic Sparrow-style BIP86 PSBT: x-only key origins on inputs
    /// and change, plus witness UTXO metadata. The end-to-end Core regtest
    /// harness independently tests consensus acceptance and fee handling.
    #[test]
    fn taproot_psbt_origin_and_change_reach_the_offline_signer() {
        let seed = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let wallet = crate::signer::Wallet::from_mnemonic(&seed, "");
        let net = Network::Regtest;
        let recv = KeyPath { change: false, index: 0 };
        let change = KeyPath { change: true, index: 0 };
        let spent_script = wallet.own_script(net, 0, recv);
        let change_script = wallet.own_script(net, 0, change);
        let destination = ScriptBuf::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();

        // Construct the previous transaction so non_witness_utxo and
        // witness_utxo can be checked against the same genuine outpoint.
        let prior = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() },
                TxOut { value: Amount::from_sat(200_000), script_pubkey: spent_script.clone() },
            ],
        };
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prior.compute_txid(), vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(75_000), script_pubkey: destination.clone() },
                TxOut { value: Amount::from_sat(123_000), script_pubkey: change_script.clone() },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(
            TxOut { value: Amount::from_sat(200_000), script_pubkey: spent_script }
        );
        psbt.inputs[0].non_witness_utxo = Some(prior);

        let fp = wallet.fingerprint();
        let recv_origin = DerivationPath::from_str("m/86h/1h/0h/0/0").unwrap();
        let change_origin = DerivationPath::from_str("m/86h/1h/0h/1/0").unwrap();
        psbt.inputs[0].tap_key_origins.insert(
            wallet.internal_key(net, 0, recv), (vec![], (fp, recv_origin))
        );
        psbt.outputs[1].tap_key_origins.insert(
            wallet.internal_key(net, 0, change), (vec![], (fp, change_origin))
        );

        // Round-trip through the exact binary serialization Sparrow can export.
        let imported = Psbt::deserialize(&psbt.serialize()).unwrap();
        let req = SignRequest::from_psbt(wallet.secp(), &imported, net).unwrap();
        assert!(matches!(req.outputs[1].dest, Dest::Own(KeyPath { change: true, index: 0 })));
        let offline = SignRequest::decode(&req.encode()).unwrap();
        let review = crate::signer::review(&wallet, &offline).unwrap();
        assert_eq!(review.fee, 2_000);
        assert_eq!(review.tx.output[0].script_pubkey, destination);
        assert_eq!(review.tx.output[1].script_pubkey, change_script);
        let signatures = crate::signer::sign(&wallet, &offline, &review).unwrap();
        let mut conflict = imported.clone();
        conflict.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(200_001);
        assert!(SignRequest::from_psbt(wallet.secp(), &conflict, net).is_err());
        assert!(crate::combine::combine(&mut conflict, &signatures).is_err());
        let mut psbt_copy = imported.clone();
        let tx = crate::combine::combine(&mut psbt_copy, &signatures).unwrap();
        assert_eq!(tx.output, review.tx.output);
        assert_eq!(tx.input[0].witness.len(), 1);

        // A coordinator that lies about its input derivation must be refused.
        let mut spoof = imported.clone();
        spoof.inputs[0].tap_key_origins.clear();
        assert!(SignRequest::from_psbt(wallet.secp(), &spoof, net).is_err());

        // With origin metadata stripped, a change output becomes an explicit
        // external output for human review, never silently classified as own.
        let mut unlabeled = imported;
        unlabeled.outputs[1].tap_key_origins.clear();
        let changed = SignRequest::from_psbt(wallet.secp(), &unlabeled, net).unwrap();
        assert!(matches!(changed.outputs[1].dest, Dest::Script(_)));
    }
}
