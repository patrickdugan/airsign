//! Seed generation. Default: operating-system randomness, optionally mixed with
//! dice. Dice-only mode uses the same rule as Coldcard (SHA-256 of the rolls
//! written as digits) so the result can be checked on any other computer with
//! `printf %s 3615... | sha256sum`.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use zeroize::Zeroizing;

use crate::codec::{err, CodecError};

pub fn entropy_bytes(words: usize) -> Result<usize, CodecError> {
    match words {
        12 => Ok(16),
        24 => Ok(32),
        _ => err("seed length must be 12 or 24 words"),
    }
}

/// Rolls of a fair d6 needed to reach the seed's entropy (log2 6 = 2.585 bits).
pub fn min_rolls(words: usize) -> usize {
    match words {
        12 => 50,
        _ => 99,
    }
}

pub fn clean_rolls(text: &str) -> Result<String, CodecError> {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '1'..='6' => out.push(c),
            c if c.is_whitespace() || c == ',' => {}
            c => return err(format!("'{c}' is not a die face (1-6)")),
        }
    }
    Ok(out)
}

pub fn os_entropy() -> Result<Zeroizing<[u8; 32]>, CodecError> {
    let mut buf = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut buf[..]).map_err(|e| CodecError(format!("operating system RNG failed: {e}")))?;
    Ok(buf)
}

/// SHA256("airsign/keygen/v1" || os || rolls): as strong as the stronger of the
/// two sources.
pub fn mixed(os: &[u8; 32], rolls: &str, words: usize) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let n = entropy_bytes(words)?;
    let mut e = sha256::Hash::engine();
    e.input(b"airsign/keygen/v1");
    e.input(os);
    e.input(rolls.as_bytes());
    let h = sha256::Hash::from_engine(e);
    Ok(Zeroizing::new(h.to_byte_array()[..n].to_vec()))
}

pub fn dice_only(rolls: &str, words: usize) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let n = entropy_bytes(words)?;
    if rolls.len() < min_rolls(words) {
        return err(format!("{} rolls needed for {} words, got {}", min_rolls(words), words, rolls.len()));
    }
    let h = sha256::Hash::hash(rolls.as_bytes());
    Ok(Zeroizing::new(h.to_byte_array()[..n].to_vec()))
}

pub fn mnemonic(entropy: &[u8]) -> Result<bip39::Mnemonic, CodecError> {
    bip39::Mnemonic::from_entropy(entropy).map_err(|e| CodecError(format!("mnemonic: {e}")))
}

/// Resolve one typed token against the BIP39 list: an exact word, or any
/// prefix of four or more letters (the list is unique in its first four).
pub fn resolve_bip39_word(token: &str) -> Option<&'static str> {
    let t = token.to_ascii_lowercase();
    let list = bip39::Language::English.word_list();
    if let Some(w) = list.iter().find(|w| **w == t) {
        return Some(w);
    }
    if t.len() >= 4 {
        let mut hits = list.iter().filter(|w| w.starts_with(&t));
        let first = hits.next()?;
        if hits.next().is_none() {
            return Some(first);
        }
    }
    None
}

/// Standard SeedQR: each word's index as four decimal digits.
pub fn standard_seedqr(m: &bip39::Mnemonic) -> Zeroizing<String> {
    let list = bip39::Language::English.word_list();
    let mut s = Zeroizing::new(String::new());
    for w in m.words() {
        let i = list.iter().position(|x| *x == w).expect("word from list");
        s.push_str(&format!("{i:04}"));
    }
    s
}

pub fn parse_standard_seedqr(digits: &str) -> Result<bip39::Mnemonic, CodecError> {
    let d = digits.trim();
    if !(d.len() == 48 || d.len() == 96) || !d.bytes().all(|b| b.is_ascii_digit()) {
        return err("not a Standard SeedQR (expected 48 or 96 digits)");
    }
    let list = bip39::Language::English.word_list();
    let mut phrase = Zeroizing::new(String::new());
    for chunk in d.as_bytes().chunks(4) {
        let i: usize = std::str::from_utf8(chunk).unwrap().parse().unwrap();
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(list.get(i).ok_or_else(|| CodecError("SeedQR word index out of range".into()))?);
    }
    bip39::Mnemonic::parse_in(bip39::Language::English, phrase.as_str()).map_err(|e| CodecError(format!("SeedQR: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dice_only_matches_sha256_of_digits() {
        let rolls = "1".repeat(99);
        let e = dice_only(&rolls, 24).unwrap();
        // printf '1%.0s' $(seq 99) | sha256sum
        let expect = sha256::Hash::hash(rolls.as_bytes()).to_byte_array();
        assert_eq!(&e[..], &expect[..]);
        assert!(dice_only("123", 24).is_err());
    }

    #[test]
    fn prefixes_resolve_uniquely() {
        assert_eq!(resolve_bip39_word("aban"), Some("abandon"));
        assert_eq!(resolve_bip39_word("ZOO"), Some("zoo"));
        assert_eq!(resolve_bip39_word("abo"), None);
        for w in bip39::Language::English.word_list() {
            assert_eq!(resolve_bip39_word(&w[..w.len().min(4)]), Some(*w));
        }
    }

    #[test]
    fn seedqr_roundtrip() {
        let m = mnemonic(&[0x11; 32]).unwrap();
        let qr = standard_seedqr(&m);
        assert_eq!(qr.len(), 96);
        assert_eq!(parse_standard_seedqr(&qr).unwrap(), m);
        // SeedQR spec example: "abandon" x11 + "about" -> 0000 x11 + 0003
        let m = bip39::Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        assert_eq!(standard_seedqr(&m).as_str(), &format!("{}0003", "0000".repeat(11)));
    }
}
