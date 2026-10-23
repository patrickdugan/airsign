//! Byte-level codecs shared by every frame: LEB128 integers, CRC32, the
//! Bytewords alphabet (base 256, BCR-2020-012), the bech32 base-32 alphabet used
//! for QR payloads, and the line-checked word transcript.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CodecError {}

pub fn err<T>(msg: impl Into<String>) -> Result<T, CodecError> {
    Err(CodecError(msg.into()))
}

// ---------------------------------------------------------------------------
// Bytewords: 256 four-letter words; the first and last letters of each word are
// unique, so "minimal" style spells a byte with two letters.

pub const BYTEWORDS: [&str; 256] = [
    "able", "acid", "also", "apex", "aqua", "arch", "atom", "aunt", "away", "axis", "back", "bald",
    "barn", "belt", "beta", "bias", "blue", "body", "brag", "brew", "bulb", "buzz", "calm", "cash",
    "cats", "chef", "city", "claw", "code", "cola", "cook", "cost", "crux", "curl", "cusp", "cyan",
    "dark", "data", "days", "deli", "dice", "diet", "door", "down", "draw", "drop", "drum", "dull",
    "duty", "each", "easy", "echo", "edge", "epic", "even", "exam", "exit", "eyes", "fact", "fair",
    "fern", "figs", "film", "fish", "fizz", "flap", "flew", "flux", "foxy", "free", "frog", "fuel",
    "fund", "gala", "game", "gear", "gems", "gift", "girl", "glow", "good", "gray", "grim", "guru",
    "gush", "gyro", "half", "hang", "hard", "hawk", "heat", "help", "high", "hill", "holy", "hope",
    "horn", "huts", "iced", "idea", "idle", "inch", "inky", "into", "iris", "iron", "item", "jade",
    "jazz", "join", "jolt", "jowl", "judo", "jugs", "jump", "junk", "jury", "keep", "keno", "kept",
    "keys", "kick", "kiln", "king", "kite", "kiwi", "knob", "lamb", "lava", "lazy", "leaf", "legs",
    "liar", "limp", "lion", "list", "logo", "loud", "love", "luau", "luck", "lung", "main", "many",
    "math", "maze", "memo", "menu", "meow", "mild", "mint", "miss", "monk", "nail", "navy", "need",
    "news", "next", "noon", "note", "numb", "obey", "oboe", "omit", "onyx", "open", "oval", "owls",
    "paid", "part", "peck", "play", "plus", "poem", "pool", "pose", "puff", "puma", "purr", "quad",
    "quiz", "race", "ramp", "real", "redo", "rich", "road", "rock", "roof", "ruby", "ruin", "runs",
    "rust", "safe", "saga", "scar", "sets", "silk", "skew", "slot", "soap", "solo", "song", "stub",
    "surf", "swan", "taco", "task", "taxi", "tent", "tied", "time", "tiny", "toil", "tomb", "toys",
    "trip", "tuna", "twin", "ugly", "undo", "unit", "urge", "user", "vast", "very", "veto", "vial",
    "vibe", "view", "visa", "void", "vows", "wall", "wand", "warm", "wasp", "wave", "waxy", "webs",
    "what", "when", "whiz", "wolf", "work", "yank", "yawn", "yell", "yoga", "yurt", "zaps", "zero",
    "zest", "zinc", "zone", "zoom",
];

fn full_word_index(word: &str) -> Option<u8> {
    BYTEWORDS.iter().position(|w| *w == word).map(|i| i as u8)
}

fn minimal_index(a: u8, b: u8) -> Option<u8> {
    BYTEWORDS
        .iter()
        .position(|w| {
            let w = w.as_bytes();
            w[0] == a && w[3] == b
        })
        .map(|i| i as u8)
}

pub fn minimal(byte: u8) -> String {
    let w = BYTEWORDS[byte as usize].as_bytes();
    format!("{}{}", w[0] as char, w[3] as char)
}

// ---------------------------------------------------------------------------
// CRC32 (IEEE 802.3, the checksum Bytewords/UR use), big-endian on the wire.

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// LEB128 unsigned integers. Decoding rejects non-minimal encodings so that every
// value has exactly one byte representation.

pub fn put_uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        if self.pos >= self.buf.len() {
            return err("frame ends early");
        }
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return err("frame ends early");
        }
        self.pos += n;
        Ok(&self.buf[self.pos - n..self.pos])
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    pub fn uleb(&mut self) -> Result<u64, CodecError> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            let chunk = (b & 0x7f) as u64;
            if i == 9 && chunk > 1 {
                return err("integer overflows 64 bits");
            }
            v |= chunk << (7 * i);
            if b & 0x80 == 0 {
                if b == 0 && i > 0 {
                    return err("non-minimal integer encoding");
                }
                return Ok(v);
            }
        }
        err("integer overflows 64 bits")
    }

    pub fn uleb_u32(&mut self, what: &str) -> Result<u32, CodecError> {
        let v = self.uleb()?;
        u32::try_from(v).map_err(|_| CodecError(format!("{what} out of range")))
    }

    pub fn finish(&self) -> Result<(), CodecError> {
        if self.remaining() != 0 {
            return err(format!("{} unexpected trailing bytes", self.remaining()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Base 32 with the bech32 alphabet (no 1/b/i/o, case-insensitive). Uppercase
// output lands in QR alphanumeric mode, 5.5 bits per character.

const B32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize].to_ascii_uppercase() as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize].to_ascii_uppercase() as char);
    }
    out
}

pub fn b32_decode(s: &str) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        let c = c.to_ascii_lowercase() as u8;
        let v = match B32.iter().position(|&x| x == c) {
            Some(v) => v as u32,
            None => return err(format!("'{}' is not a base-32 character", c as char)),
        };
        acc = ((acc << 5) | v) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return err("base-32 string has invalid padding (a character is missing or extra)");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Word transcript. The frame is prefixed with its length (LEB128) and cut into
// lines of LINE_BYTES bytes. Each line is followed by one check word
//
//     check = (index mod 256) ^ 0xa5  ^  sum over i of  a^(i+1) * b_i   in GF(2^8)
//
// with a = 2 under the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d, the one
// QR codes use for Reed-Solomon).
// Because the weights a^1..a^8 are distinct and nonzero, a single wrong word and
// any two swapped words always change the check (proofs in the tests), and a
// line typed at the wrong position always fails its index term. The length
// prefix tells the typist how many lines to expect.

pub const LINE_BYTES: usize = 8;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    p
}

fn line_check(index: usize, line: &[u8]) -> u8 {
    let mut check = (index as u8) ^ 0xa5;
    let mut weight = 1u8;
    for &b in line {
        weight = gf_mul(weight, 2);
        check ^= gf_mul(weight, b);
    }
    check
}

fn length_prefixed(frame: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(frame.len() + 2);
    put_uleb(&mut data, frame.len() as u64);
    data.extend_from_slice(frame);
    data
}

/// One rendered line: data bytes followed by its check byte.
pub fn transcript_lines(frame: &[u8]) -> Vec<Vec<u8>> {
    length_prefixed(frame)
        .chunks(LINE_BYTES)
        .enumerate()
        .map(|(i, chunk)| {
            let mut line = chunk.to_vec();
            line.push(line_check(i, chunk));
            line
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WordStyle {
    Full,
    Minimal,
}

pub fn render_transcript(frame: &[u8], style: WordStyle) -> String {
    let lines = transcript_lines(frame);
    let width = lines.len().to_string().len().max(2);
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let (data, check) = line.split_at(line.len() - 1);
        let words: Vec<String> = data
            .iter()
            .map(|&b| match style {
                WordStyle::Full => BYTEWORDS[b as usize].to_string(),
                WordStyle::Minimal => minimal(b),
            })
            .collect();
        let check = match style {
            WordStyle::Full => BYTEWORDS[check[0] as usize].to_string(),
            WordStyle::Minimal => minimal(check[0]),
        };
        let sep = if style == WordStyle::Full { " " } else { "" };
        out.push_str(&format!("{:>width$}  {}  : {}\n", i + 1, words.join(sep), check));
    }
    out
}

/// Turn the letters a person typed for one line into bytes. Accepts full words
/// separated by spaces, or minimal two-letter codes with or without spaces.
/// Returns every reading that parses (full words first); the caller keeps the
/// one whose check word matches. Both can parse when minimal codes are typed in
/// groups of four that happen to spell words ("la"+"va" is "lava").
pub fn parse_line_candidates(text: &str) -> Result<Vec<Vec<u8>>, CodecError> {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_ascii_alphabetic() { c.to_ascii_lowercase() } else { ' ' })
        .collect();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    if tokens.is_empty() {
        return err("no words on this line");
    }
    let mut readings = Vec::new();
    if tokens.iter().all(|t| t.len() == 4) {
        if let Some(bytes) = tokens.iter().map(|t| full_word_index(t)).collect::<Option<Vec<u8>>>() {
            readings.push(bytes);
        }
    }
    let letters = tokens.concat().into_bytes();
    let minimal: Result<Vec<u8>, CodecError> = if letters.len() % 2 != 0 {
        err("odd number of letters; minimal style uses exactly two letters per word")
    } else {
        letters
            .chunks(2)
            .map(|p| {
                minimal_index(p[0], p[1]).ok_or_else(|| {
                    CodecError(format!("'{}{}' is not a two-letter word code", p[0] as char, p[1] as char))
                })
            })
            .collect()
    };
    match minimal {
        Ok(bytes) => readings.push(bytes),
        Err(e) if readings.is_empty() => {
            let four = tokens.iter().filter(|t| t.len() == 4).count();
            if four * 2 > tokens.len() {
                let bad: Vec<&str> = tokens.iter().filter(|t| full_word_index(t).is_none()).copied().collect();
                return err(format!("not on the word list: {}", bad.join(", ")));
            }
            return Err(e);
        }
        Err(_) => {}
    }
    Ok(readings)
}

pub fn parse_line_tokens(text: &str) -> Result<Vec<u8>, CodecError> {
    Ok(parse_line_candidates(text)?.swap_remove(0))
}

/// Incremental decoder used by the interactive prompt: feed one line at a time.
pub struct TranscriptReader {
    lines_seen: usize,
    data: Vec<u8>,
    expected_len: Option<usize>,
}

pub enum LineResult {
    NeedMore { line: usize, total: Option<usize> },
    Done(Vec<u8>),
}

impl Default for TranscriptReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TranscriptReader {
    pub fn new() -> Self {
        TranscriptReader { lines_seen: 0, data: Vec::new(), expected_len: None }
    }

    pub fn total_lines(&self) -> Option<usize> {
        self.expected_len.map(|n| {
            let mut prefix = Vec::new();
            put_uleb(&mut prefix, n as u64);
            (prefix.len() + n).div_ceil(LINE_BYTES)
        })
    }

    pub fn next_line_number(&self) -> usize {
        self.lines_seen + 1
    }

    pub fn push_line(&mut self, text: &str) -> Result<LineResult, CodecError> {
        let readings = parse_line_candidates(text)?;
        let line_no = self.lines_seen + 1;
        let mut matched = None;
        let mut too_long = false;
        for bytes in &readings {
            if bytes.len() < 2 {
                continue;
            }
            let (body, check) = bytes.split_at(bytes.len() - 1);
            if body.len() > LINE_BYTES {
                too_long = true;
                continue;
            }
            if line_check(self.lines_seen, body) == check[0] {
                matched = Some(body.to_vec());
                break;
            }
        }
        let body = match matched {
            Some(b) => b,
            None if too_long => {
                return err(format!("line {line_no}: too many words (at most {LINE_BYTES} plus the check word)"))
            }
            None => {
                return err(format!(
                    "line {line_no} does not match its check word; re-read and retype this line"
                ))
            }
        };
        let body = &body[..];
        let mut data = self.data.clone();
        data.extend_from_slice(body);
        // A failed line cannot mutate the transcript length or cursor.
        let expected_len = match self.expected_len {
            Some(n) => n,
            None => {
                let mut r = Reader::new(&data);
                let n = r.uleb().map_err(|_| CodecError("bad length prefix on line 1".into()))? as usize;
                if n == 0 || n > 4096 {
                    return err("length prefix on line 1 is out of range");
                }
                n
            }
        };
        let mut prefix = Vec::new();
        put_uleb(&mut prefix, expected_len as u64);
        let total = (prefix.len() + expected_len).div_ceil(LINE_BYTES);
        let is_last = self.lines_seen + 1 == total;
        if !is_last && body.len() != LINE_BYTES {
            return err(format!("line {} should have {} words plus the check word", self.lines_seen + 1, LINE_BYTES));
        }
        if is_last {
            let mut r = Reader::new(&data);
            let n = r.uleb()? as usize;
            let frame = r.bytes(n).map_err(|_| CodecError("last line is too short".into()))?.to_vec();
            r.finish().map_err(|_| CodecError("last line has extra words".into()))?;
            self.data = data;
            self.expected_len = Some(expected_len);
            self.lines_seen += 1;
            return Ok(LineResult::Done(frame));
        }
        self.data = data;
        self.expected_len = Some(expected_len);
        self.lines_seen += 1;
        Ok(LineResult::NeedMore { line: self.lines_seen + 1, total: Some(total) })
    }
}

/// Decode a whole transcript pasted or typed as one block of text.
pub fn parse_transcript(text: &str) -> Result<Vec<u8>, CodecError> {
    let lines: Vec<&str> = text.lines().filter(|l| l.chars().any(|c| c.is_ascii_alphabetic())).collect();
    let mut reader = TranscriptReader::new();
    if lines.len() > 1 {
        for (i, line) in lines.iter().enumerate() {
            if let LineResult::Done(frame) = reader.push_line(line)? {
                if i + 1 != lines.len() {
                    return err("extra lines after the completed transcript");
                }
                return Ok(frame);
            }
        }
        return err("transcript ended before its last line");
    }
    // A single run of text: rebuild the lines from the word stream.
    let bytes = parse_line_tokens(text)?;
    let mut pos = 0;
    while pos < bytes.len() {
        let remaining = bytes.len() - pos;
        let take = remaining.min(LINE_BYTES + 1);
        let expected = match reader.total_lines() {
            Some(total) if reader.next_line_number() == total => {
                let n = reader.expected_len.unwrap();
                let mut prefix = Vec::new();
                put_uleb(&mut prefix, n as u64);
                (prefix.len() + n) - (total - 1) * LINE_BYTES + 1
            }
            _ => take,
        };
        if expected > remaining {
            return err("transcript ended before its last line");
        }
        let chunk: Vec<String> = bytes[pos..pos + expected].iter().map(|&b| BYTEWORDS[b as usize].to_string()).collect();
        pos += expected;
        if let LineResult::Done(frame) = reader.push_line(&chunk.join(" "))? {
            if pos != bytes.len() {
                return err("extra words after the last line");
            }
            return Ok(frame);
        }
    }
    err("transcript ended before its last line")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_first_line_does_not_poison_transcript_state() {
        let frame = crate::frame::seal(crate::frame::Kind::Request, &[7u8; 20]);
        let partial = [frame.len() as u8];
        let first = format!(
            "{} {}",
            BYTEWORDS[partial[0] as usize],
            BYTEWORDS[line_check(0, &partial) as usize]
        );
        let mut reader = TranscriptReader::new();
        assert!(reader.push_line(&first).is_err());
        assert_eq!(reader.total_lines(), None);
        let text = render_transcript(&frame, WordStyle::Full);
        let mut result = None;
        for line in text.lines() {
            if let LineResult::Done(f) = reader.push_line(line).unwrap() {
                result = Some(f);
            }
        }
        assert_eq!(result, Some(frame));
        assert!(parse_transcript(&format!("{text}able able\n")).is_err());
    }

    #[test]
    fn bytewords_list_properties() {
        let mut seen = std::collections::HashSet::new();
        let mut pairs = std::collections::HashSet::new();
        for w in BYTEWORDS {
            assert_eq!(w.len(), 4, "{w}");
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
            assert!(seen.insert(w), "duplicate {w}");
            let b = w.as_bytes();
            assert!(pairs.insert((b[0], b[3])), "first/last letters not unique: {w}");
        }
        let mut sorted = BYTEWORDS.to_vec();
        sorted.sort();
        assert_eq!(sorted, BYTEWORDS.to_vec(), "list is alphabetical in the spec");
    }

    #[test]
    fn bytewords_reference_vector() {
        // bc-ur reference: bytes [0, 1, 2, 128, 255] with CRC32 appended.
        let data = [0u8, 1, 2, 128, 255];
        let mut all = data.to_vec();
        all.extend_from_slice(&crc32(&data).to_be_bytes());
        let words: Vec<&str> = all.iter().map(|&b| BYTEWORDS[b as usize]).collect();
        assert_eq!(words.join(" "), "able acid also lava zoom jade need echo taxi");
        let min: String = all.iter().map(|&b| minimal(b)).collect();
        assert_eq!(min, "aeadaolazmjendeoti");
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn uleb_roundtrip_and_minimality() {
        for v in [0u64, 1, 127, 128, 255, 300, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            put_uleb(&mut b, v);
            let mut r = Reader::new(&b);
            assert_eq!(r.uleb().unwrap(), v);
            r.finish().unwrap();
        }
        assert!(Reader::new(&[0x80, 0x00]).uleb().is_err());
        assert!(Reader::new(&[0xff; 11]).uleb().is_err());
    }

    #[test]
    fn b32_roundtrip_and_padding() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = b32_encode(&data);
            assert_eq!(b32_decode(&s).unwrap(), data);
            assert_eq!(b32_decode(&s.to_lowercase()).unwrap(), data);
        }
        // An extra trailing character is excess padding.
        let s = b32_encode(&[1, 2, 3]);
        assert!(b32_decode(&format!("{s}Q")).is_err());
    }

    #[test]
    fn transcript_roundtrip_all_styles() {
        for n in [1usize, 7, 8, 9, 63, 64, 65, 127, 128, 200, 700] {
            let frame: Vec<u8> = (0..n).map(|i| (i * 131 + 7) as u8).collect();
            let full = render_transcript(&frame, WordStyle::Full);
            assert_eq!(parse_transcript(&full).unwrap(), frame, "full n={n}");
            let min = render_transcript(&frame, WordStyle::Minimal);
            assert_eq!(parse_transcript(&min).unwrap(), frame, "minimal n={n}");
            let one_run: String = full.lines().map(|l| l.split(':').map(|p| p.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ')).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join(" ");
            assert_eq!(parse_transcript(&one_run).unwrap(), frame, "one run n={n}");
        }
    }

    #[test]
    fn transcript_catches_typo_and_names_line() {
        let frame: Vec<u8> = (0..40u8).collect();
        let text = render_transcript(&frame, WordStyle::Full);
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        // Replace the third word of line 3 with a different valid word.
        let mut parts: Vec<String> = lines[2].split_whitespace().map(String::from).collect();
        parts[3] = if parts[3] == "zoom" { "able".into() } else { "zoom".into() };
        lines[2] = parts.join(" ");
        let e = parse_transcript(&lines.join("\n")).unwrap_err();
        assert!(e.0.contains("line 3"), "{e}");
    }

    #[test]
    fn transcript_catches_swapped_lines() {
        let frame: Vec<u8> = (0..40u8).collect();
        let text = render_transcript(&frame, WordStyle::Full);
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(1, 2);
        assert!(parse_transcript(&lines.join("\n")).is_err());
    }

    #[test]
    fn line_weights_are_distinct_and_nonzero() {
        // The detection guarantees rest on this: a^1..a^8 distinct and nonzero,
        // so a*d != 0 for any nonzero d (single substitution) and
        // (a^i + a^j)*d != 0 for i != j (any transposition).
        let mut w = 1u8;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..LINE_BYTES {
            w = gf_mul(w, 2);
            assert_ne!(w, 0);
            assert!(seen.insert(w));
        }
        // 2 generates the whole multiplicative group (order 255).
        let mut x = 1u8;
        for k in 1..=255 {
            x = gf_mul(x, 2);
            assert_eq!(x == 1, k == 255);
        }
    }

    #[test]
    fn line_check_catches_every_substitution_and_transposition() {
        let body = [3u8, 1, 4, 1, 5, 9, 2, 6];
        let check = line_check(4, &body);
        for pos in 0..body.len() {
            for v in 0..=255u8 {
                if v == body[pos] {
                    continue;
                }
                let mut b = body;
                b[pos] = v;
                assert_ne!(line_check(4, &b), check, "pos {pos} value {v}");
            }
            for other in 0..body.len() {
                if body[other] != body[pos] {
                    let mut b = body;
                    b.swap(pos, other);
                    assert_ne!(line_check(4, &b), check, "swap {pos} {other}");
                }
            }
        }
        for index in 0..256 {
            if index != 4 {
                assert_ne!(line_check(index, &body), check, "line typed at position {index}");
            }
        }
    }
}
