//! Frame envelope, network codes, the watch-only ACCOUNT frame, and the
//! SIGNATURES frame. The SIGN_REQUEST frame lives in `request.rs`.
//!
//! frame := header(1) || body || crc32_be(header || body)
//!   header = version << 4 | kind
//! SIGNATURES frames carry no CRC: each 64-byte BIP340 signature is checked
//! against its sighash by the coordinator, which is a stronger check than any
//! checksum, and dropping it saves four words on the hand-typed return path.

use std::str::FromStr;

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{Network, NetworkKind};

use crate::codec::{self, b32_decode, b32_encode, crc32, err, put_uleb, CodecError, Reader};

pub const VERSION: u8 = 1;
pub const QR_PREFIX: &str = "AS1";
pub const MAX_FRAME: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Account = 1,
    Request = 2,
    Signatures = 3,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Account => "watch-only account",
            Kind::Request => "signing request",
            Kind::Signatures => "signatures",
        }
    }
}

pub fn net_code(n: Network) -> u8 {
    match n {
        Network::Bitcoin => 0,
        Network::Signet => 2,
        Network::Regtest => 3,
        _ => 1, // testnet3 / testnet4 share address encoding and coin type
    }
}

pub fn net_from_code(c: u8) -> Network {
    match c & 3 {
        0 => Network::Bitcoin,
        1 => Network::Testnet,
        2 => Network::Signet,
        _ => Network::Regtest,
    }
}

pub fn parse_network(s: &str) -> Result<Network, CodecError> {
    match s.to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "test" | "testnet" | "testnet3" | "testnet4" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => err(format!("unknown network '{s}'")),
    }
}

pub fn coin_type(n: Network) -> u32 {
    if n == Network::Bitcoin {
        0
    } else {
        1
    }
}

pub fn seal(kind: Kind, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(body.len() + 5);
    f.push(VERSION << 4 | kind as u8);
    f.extend_from_slice(body);
    if kind != Kind::Signatures {
        let c = crc32(&f);
        f.extend_from_slice(&c.to_be_bytes());
    }
    f
}

pub fn open(frame: &[u8]) -> Result<(Kind, &[u8]), CodecError> {
    if frame.is_empty() {
        return err("empty frame");
    }
    if frame.len() > MAX_FRAME {
        return err("frame too large");
    }
    let version = frame[0] >> 4;
    if version != VERSION {
        return err(format!("frame version {version} is not supported (this build reads version {VERSION})"));
    }
    let kind = match frame[0] & 0x0f {
        1 => Kind::Account,
        2 => Kind::Request,
        3 => Kind::Signatures,
        k => return err(format!("unknown frame kind {k}")),
    };
    if kind == Kind::Signatures {
        return Ok((kind, &frame[1..]));
    }
    if frame.len() < 5 {
        return err("frame too short");
    }
    let (head, tail) = frame.split_at(frame.len() - 4);
    if crc32(head).to_be_bytes() != tail {
        return err("frame checksum mismatch (a word or character was mistyped or misread)");
    }
    Ok((kind, &head[1..]))
}

pub fn expect(frame: &[u8], want: Kind) -> Result<&[u8], CodecError> {
    let (kind, body) = open(frame)?;
    if kind != want {
        return err(format!("expected a {} but this is a {}", want.name(), kind.name()));
    }
    Ok(body)
}

pub fn to_qr_string(frame: &[u8]) -> String {
    format!("{QR_PREFIX}{}", b32_encode(frame))
}

/// Accept either a QR/base-32 string ("AS1...") or a word transcript.
pub fn parse_text(text: &str) -> Result<Vec<u8>, CodecError> {
    // Bound untrusted QR or typed inputs before allocating a compact copy.
    if text.len() > MAX_FRAME * 16 {
        return err("frame text exceeds the maximum length");
    }
    let compact: String = text.split_whitespace().collect();
    // A Unicode prefix must yield a parse error, never a byte-boundary panic.
    if compact.get(..3).is_some_and(|prefix| prefix.eq_ignore_ascii_case(QR_PREFIX)) {
        return b32_decode(&compact[3..]);
    }
    codec::parse_transcript(text)
}

// ---------------------------------------------------------------------------
// ACCOUNT: what the online coordinator needs to build a watch-only wallet for
// m/86'/coin'/account'. 80 bytes framed.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub network: Network,
    pub master_fp: Fingerprint,
    pub account: u32,
    pub parent_fp: Fingerprint,
    pub chain_code: ChainCode,
    pub pubkey: PublicKey,
}

impl Account {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(80);
        b.push(net_code(self.network));
        b.extend_from_slice(self.master_fp.as_bytes());
        put_uleb(&mut b, self.account as u64);
        b.extend_from_slice(self.parent_fp.as_bytes());
        b.extend_from_slice(self.chain_code.as_bytes());
        b.extend_from_slice(&self.pubkey.serialize());
        seal(Kind::Account, &b)
    }

    pub fn decode(frame: &[u8]) -> Result<Self, CodecError> {
        let body = expect(frame, Kind::Account)?;
        let mut r = Reader::new(body);
        let flags = r.u8()?;
        if flags & !3 != 0 {
            return err("unknown account flags");
        }
        let master_fp = Fingerprint::from(r.array::<4>()?);
        let account = r.uleb_u32("account")?;
        if account >= 1 << 31 {
            return err("account index out of range");
        }
        let parent_fp = Fingerprint::from(r.array::<4>()?);
        let chain_code = ChainCode::from(r.array::<32>()?);
        let pubkey = PublicKey::from_slice(r.bytes(33)?).map_err(|_| CodecError("invalid public key".into()))?;
        r.finish()?;
        Ok(Account { network: net_from_code(flags), master_fp, account, parent_fp, chain_code, pubkey })
    }

    pub fn xpub(&self) -> Xpub {
        Xpub {
            network: NetworkKind::from(self.network),
            depth: 3,
            parent_fingerprint: self.parent_fp,
            child_number: ChildNumber::from_hardened_idx(self.account).expect("checked < 2^31"),
            public_key: self.pubkey,
            chain_code: self.chain_code,
        }
    }

    pub fn origin(&self) -> String {
        format!("[{}/86h/{}h/{}h]", self.master_fp, coin_type(self.network), self.account)
    }

    /// (receive, change) descriptors with BIP380 checksums, ready for
    /// Bitcoin Core's `importdescriptors`.
    pub fn descriptors(&self) -> (String, String) {
        let x = self.xpub();
        let recv = format!("tr({}{}/0/*)", self.origin(), x);
        let change = format!("tr({}{}/1/*)", self.origin(), x);
        (descriptor_with_checksum(&recv), descriptor_with_checksum(&change))
    }
}

// ---------------------------------------------------------------------------
// SIGNATURES: header || 64-byte BIP340 signatures in input order.

pub fn encode_signatures(sigs: &[schnorr::Signature]) -> Vec<u8> {
    let mut b = Vec::with_capacity(sigs.len() * 64);
    for s in sigs {
        b.extend_from_slice(s.as_ref());
    }
    seal(Kind::Signatures, &b)
}

pub fn decode_signatures(frame: &[u8]) -> Result<Vec<schnorr::Signature>, CodecError> {
    let body = expect(frame, Kind::Signatures)?;
    if body.is_empty() || body.len() % 64 != 0 {
        return err("signature frame length is not a multiple of 64 bytes");
    }
    body.chunks(64)
        .map(|c| schnorr::Signature::from_slice(c).map_err(|_| CodecError("malformed signature".into())))
        .collect()
}

// ---------------------------------------------------------------------------
// BIP380 descriptor checksum.

const DESC_INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const DESC_CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn desc_polymod(symbols: &[u64]) -> u64 {
    const GEN: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];
    let mut chk: u64 = 1;
    for &v in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7_ffff_ffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

pub fn descriptor_checksum(desc: &str) -> Option<String> {
    let mut symbols = Vec::new();
    let mut groups = Vec::new();
    for c in desc.chars() {
        let v = DESC_INPUT_CHARSET.find(c)? as u64;
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    match groups.len() {
        1 => symbols.push(groups[0]),
        2 => symbols.push(groups[0] * 3 + groups[1]),
        _ => {}
    }
    symbols.extend_from_slice(&[0; 8]);
    let c = desc_polymod(&symbols) ^ 1;
    Some((0..8).map(|i| DESC_CHECKSUM_CHARSET[((c >> (5 * (7 - i))) & 31) as usize] as char).collect())
}

pub fn descriptor_with_checksum(desc: &str) -> String {
    format!("{desc}#{}", descriptor_checksum(desc).expect("descriptor uses valid characters"))
}

pub fn fingerprint_from_hex(s: &str) -> Result<Fingerprint, CodecError> {
    Fingerprint::from_str(s).map_err(|_| CodecError(format!("'{s}' is not an 8-hex-digit fingerprint")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_checksum_bip380_vector() {
        assert_eq!(descriptor_checksum("raw(deadbeef)").unwrap(), "89f8spxm");
    }

    #[test]
    fn frame_crc_catches_corruption() {
        let f = seal(Kind::Request, &[1, 2, 3, 4, 5]);
        assert!(open(&f).is_ok());
        for i in 0..f.len() {
            let mut g = f.clone();
            g[i] ^= 0x10;
            assert!(open(&g).is_err(), "byte {i}");
        }
    }

    #[test]
    fn malformed_unicode_and_oversize_frames_are_rejected() {
        for text in ["éAS1QQ", "🙂AS1QQ", "ASé", "𐀀"] {
            assert!(parse_text(text).is_err(), "{text}");
        }
        assert!(parse_text(&"A".repeat(MAX_FRAME * 16 + 1)).is_err());
    }

    #[test]
    fn qr_string_roundtrip() {
        let f = seal(Kind::Account, &[9; 70]);
        let s = to_qr_string(&f);
        assert!(s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert_eq!(parse_text(&s).unwrap(), f);
        assert_eq!(parse_text(&s.to_lowercase()).unwrap(), f);
    }
}
