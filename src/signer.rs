//! Offline side: hold a BIP39 seed for one session, rebuild the transaction a
//! request describes, explain it, and sign it.
//!
//! Signatures use BIP340 with an all-zero aux_rand, which is what Bitcoin Core
//! does (`script/sign.cpp`, CreateSchnorrSig). The signature is therefore a pure
//! function of key and transaction: any other implementation holding the same
//! key, Core included, reproduces it byte for byte. A tampered build that tried
//! to leak the seed through nonce choice ("Dark Skippy") would be caught by that
//! comparison.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr, All, Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{absolute::LockTime, Address, Amount, Network, NetworkKind, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use zeroize::Zeroizing;

use crate::codec::{err, CodecError};
use crate::frame::{coin_type, Account};
use crate::request::{xonly_of_p2tr, Dest, KeyPath, SignRequest};

/// Change or receive index above this draws a warning: a coordinator can hide
/// change at an index the user's wallet will never scan ("ransom" change).
pub const HIGH_INDEX_WARNING: u32 = 1_000;

pub struct Wallet {
    secp: Secp256k1<All>,
    master: Xpriv,
    fp: Fingerprint,
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.master.private_key.non_secure_erase();
    }
}

impl Wallet {
    pub fn from_mnemonic(m: &bip39::Mnemonic, passphrase: &str) -> Self {
        let seed = Zeroizing::new(m.to_seed(passphrase));
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Main, &seed[..]).expect("64-byte seed");
        let fp = master.fingerprint(&secp);
        Wallet { secp, master, fp }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fp
    }

    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn account_path(network: Network, account: u32) -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(coin_type(network)).unwrap(),
            ChildNumber::from_hardened_idx(account).expect("account < 2^31"),
        ])
    }

    fn account_xpriv(&self, network: Network, account: u32) -> Xpriv {
        let mut x = self
            .master
            .derive_priv(&self.secp, &Self::account_path(network, account))
            .expect("hardened derivation");
        x.network = NetworkKind::from(network);
        x
    }

    pub fn account_export(&self, network: Network, account: u32) -> Account {
        let mut x = self.account_xpriv(network, account);
        let xpub = Xpub::from_priv(&self.secp, &x);
        x.private_key.non_secure_erase();
        Account {
            network,
            master_fp: self.fp,
            account,
            parent_fp: xpub.parent_fingerprint,
            chain_code: xpub.chain_code,
            pubkey: xpub.public_key,
        }
    }

    fn keypair(&self, network: Network, account: u32, path: KeyPath) -> Keypair {
        let tail = [
            ChildNumber::from_normal_idx(path.change as u32).unwrap(),
            ChildNumber::from_normal_idx(path.index).expect("index < 2^31"),
        ];
        let mut account_key = self.account_xpriv(network, account);
        let mut child = account_key.derive_priv(&self.secp, &tail).expect("derivation");
        account_key.private_key.non_secure_erase();
        let pair = Keypair::from_secret_key(&self.secp, &child.private_key);
        child.private_key.non_secure_erase();
        pair
    }

    pub fn internal_key(&self, network: Network, account: u32, path: KeyPath) -> XOnlyPublicKey {
        self.keypair(network, account, path).x_only_public_key().0
    }

    pub fn own_script(&self, network: Network, account: u32, path: KeyPath) -> ScriptBuf {
        ScriptBuf::new_p2tr(&self.secp, self.internal_key(network, account, path), None)
    }

    /// The address to verify against an online coordinator before funding.
    /// Derive it locally from the same key path used when signing.
    pub fn receive_address(&self, network: Network, account: u32, index: u32) -> Address {
        let script = self.own_script(network, account, KeyPath { change: false, index });
        Address::from_script(&script, network).expect("BIP86 has a standard receiving address")
    }

    /// BIP32 extended private key descriptor for the account, so a test can
    /// load the same key into Bitcoin Core and compare signatures.
    #[cfg(feature = "dev")]
    pub fn dev_private_descriptors(&self, network: Network, account: u32) -> (String, String) {
        let x = self.account_xpriv(network, account);
        let origin = format!("[{}/86h/{}h/{}h]", self.fp, coin_type(network), account);
        (
            crate::frame::descriptor_with_checksum(&format!("tr({origin}{x}/0/*)")),
            crate::frame::descriptor_with_checksum(&format!("tr({origin}{x}/1/*)")),
        )
    }
}

pub struct Review {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub fee: u64,
    pub vsize: u64,
    pub summary: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Addresses in groups of four, which is how people compare them across screens.
pub fn grouped(s: &str) -> String {
    s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
}

pub fn describe_script(spk: &ScriptBuf, network: Network) -> (String, bool) {
    match Address::from_script(spk, network) {
        Ok(a) => (grouped(&a.to_string()), true),
        Err(_) if spk.is_op_return() => (format!("OP_RETURN data {}", spk.to_hex_string()), false),
        Err(_) => (format!("non-standard script {}", spk.to_hex_string()), false),
    }
}

fn dust_limit(spk: &ScriptBuf) -> u64 {
    if spk.is_op_return() {
        0
    } else if spk.is_p2tr() || spk.is_p2wsh() {
        330
    } else if spk.is_p2wpkh() {
        294
    } else {
        546
    }
}

pub fn review(w: &Wallet, req: &SignRequest) -> Result<Review, CodecError> {
    if req.master_fp != w.fp {
        return err(format!(
            "this request is for wallet {} but the seed you entered is wallet {}; \
             check the words and the passphrase",
            req.master_fp, w.fp
        ));
    }
    let net = req.network;
    let mut warnings = Vec::new();
    let mut summary = Vec::new();

    let prevouts: Vec<TxOut> = req
        .inputs
        .iter()
        .map(|i| TxOut { value: Amount::from_sat(i.amount), script_pubkey: w.own_script(net, req.account, i.path) })
        .collect();
    let mut outputs = Vec::with_capacity(req.outputs.len());
    let total_in = req.total_in();
    let total_out = req.total_out();
    if total_out > total_in {
        return err(format!("outputs ({} BTC) exceed inputs ({} BTC)", btc(total_out), btc(total_in)));
    }
    let fee = total_in - total_out;

    let net_name = match net {
        Network::Bitcoin => "MAINNET",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
        _ => "testnet",
    };
    summary.push(format!("Wallet {}  account {}  ({net_name})", w.fp, req.account));
    summary.push(format!(
        "Spending {} coin{} worth {} BTC",
        req.inputs.len(),
        if req.inputs.len() == 1 { "" } else { "s" },
        btc(total_in)
    ));
    for i in &req.inputs {
        if i.path.index >= HIGH_INDEX_WARNING {
            warnings.push(format!("input key index {} is unusually high", i.path.index));
        }
    }
    let mut external = 0u64;
    for (n, o) in req.outputs.iter().enumerate() {
        let spk = match &o.dest {
            Dest::Own(p) => {
                let what = if p.change { "CHANGE" } else { "TO SELF" };
                summary.push(format!(
                    "  #{:<2} {:<8} {} BTC  to your own address {} (derived here)",
                    n,
                    what,
                    btc(o.amount),
                    p.describe(net, req.account)
                ));
                if p.index >= HIGH_INDEX_WARNING {
                    warnings.push(format!(
                        "output #{n} goes to your address index {}; wallets that scan only the first few \
                         thousand addresses will not see it",
                        p.index
                    ));
                }
                w.own_script(net, req.account, *p)
            }
            Dest::Script(spk) => {
                external += o.amount;
                let (text, standard) = describe_script(spk, net);
                summary.push(format!("  #{:<2} {:<8} {} BTC  to {}", n, "SEND", btc(o.amount), text));
                if !standard && !spk.is_op_return() {
                    warnings.push(format!("output #{n} is not a standard address"));
                }
                spk.clone()
            }
        };
        if o.amount < dust_limit(&spk) {
            warnings.push(format!("output #{n} is below the dust limit and may not relay"));
        }
        outputs.push(TxOut { value: Amount::from_sat(o.amount), script_pubkey: spk });
    }

    let tx = Transaction {
        version: Version(req.version as i32),
        lock_time: LockTime::from_consensus(req.lock_time),
        input: req
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(req.sequence),
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    let mut sized = tx.clone();
    for i in &mut sized.input {
        i.witness = Witness::from_slice(&[[0u8; 64]]);
    }
    let vsize = sized.weight().to_vbytes_ceil();
    let rate = fee as f64 / vsize as f64;
    summary.push(format!("  FEE          {} BTC  ({} sat, {:.1} sat/vB over {} vB)", btc(fee), fee, rate, vsize));
    if external == 0 {
        summary.push("  Nothing leaves the wallet: this is a self-transfer or consolidation.".into());
    }
    if req.lock_time != 0 && req.sequence != 0xffff_ffff {
        if req.lock_time < 500_000_000 {
            summary.push(format!("  Not valid before block {}", req.lock_time));
        } else {
            summary.push(format!("  Not valid before unix time {}", req.lock_time));
        }
    }
    if req.sequence < 0xffff_fffe {
        summary.push("  Replaceable (RBF): yes".into());
    }
    if rate > 500.0 {
        warnings.push(format!("fee rate {rate:.0} sat/vB is very high"));
    }
    if fee > 1_000_000 || (fee > 50_000 && fee * 20 > total_in) {
        warnings.push(format!("fee is {} BTC, {:.1}% of the coins spent", btc(fee), 100.0 * fee as f64 / total_in as f64));
    }
    if !(1..=3).contains(&req.version) {
        warnings.push(format!("transaction version {} is non-standard", req.version));
    }
    Ok(Review { tx, prevouts, fee, vsize, summary, warnings })
}

pub fn sign(w: &Wallet, req: &SignRequest, rv: &Review) -> Result<Vec<schnorr::Signature>, CodecError> {
    let mut cache = SighashCache::new(&rv.tx);
    let prevouts = Prevouts::All(&rv.prevouts);
    let mut sigs = Vec::with_capacity(req.inputs.len());
    for (n, input) in req.inputs.iter().enumerate() {
        let mut keypair = w.keypair(req.network, req.account, input.path);
        let mut tweaked = keypair.tap_tweak(&w.secp, None).to_keypair();
        let output_key = tweaked.x_only_public_key().0;
        if xonly_of_p2tr(&rv.prevouts[n].script_pubkey) != Some(output_key) {
            return err(format!("internal error: input {n} key does not match its script"));
        }
        let sighash = cache
            .taproot_key_spend_signature_hash(n, &prevouts, TapSighashType::Default)
            .map_err(|e| CodecError(format!("sighash for input {n}: {e}")))?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = w.secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
        keypair.non_secure_erase();
        tweaked.non_secure_erase();
        w.secp
            .verify_schnorr(&sig, &msg, &output_key)
            .map_err(|_| CodecError(format!("signature for input {n} failed self-check; not releasing it")))?;
        sigs.push(sig);
    }
    Ok(sigs)
}

#[cfg(test)]
mod bip86_address_tests {
    use super::*;

    #[test]
    fn receiving_address_matches_bip86_reference_vector() {
        let m = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let w = Wallet::from_mnemonic(&m, "");
        // BIP86 official test vectors, first two receive addresses.
        assert_eq!(
            w.receive_address(Network::Bitcoin, 0, 0).to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        );
        assert_eq!(
            w.receive_address(Network::Bitcoin, 0, 1).to_string(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
        );
    }
}
