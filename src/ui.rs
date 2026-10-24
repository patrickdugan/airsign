//! Interactive console flows for the offline machine. Plain line-oriented I/O
//! so it runs on a bare Linux text console with no display server.

use std::io::{self, BufRead, Write};

use bitcoin::Network;
use zeroize::{Zeroize, Zeroizing};

use crate::codec::{render_transcript, CodecError, LineResult, TranscriptReader, WordStyle};
use crate::frame::{self, encode_signatures, parse_network, to_qr_string};
use crate::harden;
use crate::keygen;
use crate::qr;
use crate::request::SignRequest;
use crate::signer::{self, Wallet};

pub struct Session {
    pub camera: String,
    pub live: bool,
}

fn clear() {
    print!("\x1b[3J\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

/// Read one line. EOF ends the program: on the live image that powers off.
pub fn prompt(label: &str) -> String {
    print!("{label}");
    let _ = io::stdout().flush();
    let mut s = String::new();
    match io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => {
            println!();
            std::process::exit(0);
        }
        Ok(_) => s.trim().to_string(),
    }
}

/// Read sensitive input directly into a zeroizing buffer, trimming in place
/// so the original line is never left in an ordinary String allocation.
fn prompt_secret(label: &str) -> Zeroizing<String> {
    print!("{label}");
    let _ = io::stdout().flush();
    // Mnemonics, backup verification and dice rolls must never echo onto tty1.
    let mut s = match harden::read_line_noecho() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("Secure input unavailable: {e}");
            std::process::exit(0);
        }
    };
    let end = s.trim_end().len();
    s.truncate(end);
    let leading = s.len() - s.trim_start().len();
    if leading > 0 {
        s.drain(..leading);
    }
    s
}

fn pause(label: &str) {
    prompt(label);
}

fn backup_word_matches(expected: &str, typed: &str) -> bool {
    keygen::resolve_bip39_word(typed) == Some(expected)
}

fn show_first_receive_address(w: &Wallet, network: Network, account: u32) {
    clear();
    println!("First receiving address, derived on this OFFLINE computer:");
    println!("  m/86h/{}h/{}h/0/0", frame::coin_type(network), account);
    println!("  {}", w.receive_address(network, account, 0));
    println!();
    println!("Record this address and compare it character-for-character with the");
    println!("online watch-only wallet's first receive address BEFORE depositing BTC.");
    println!("You can repeat this check from menu option 3 at any time.");
    pause("\n[Enter] display the watch-only account QR: ");
}

fn ask_network() -> Network {
    loop {
        let a = prompt("Network: [m]ainnet, [t]estnet, [s]ignet, [r]egtest (Enter = mainnet): ");
        let n = match a.to_ascii_lowercase().as_str() {
            "" | "m" => Ok(Network::Bitcoin),
            "t" => Ok(Network::Testnet),
            "s" => Ok(Network::Signet),
            "r" => Ok(Network::Regtest),
            other => parse_network(other),
        };
        match n {
            Ok(n) => return n,
            Err(e) => println!("  {e}"),
        }
    }
}

fn ask_word_count() -> usize {
    loop {
        match prompt("How many seed words? [24] or 12: ").as_str() {
            "" | "24" => return 24,
            "12" => return 12,
            _ => println!("  Type 12 or 24."),
        }
    }
}

/// Seed entry: words (four-letter prefixes are enough) or a Standard SeedQR.
pub fn load_wallet(s: &Session) -> Option<Wallet> {
    let count = ask_word_count();
    let mnemonic = loop {
        println!("Type your {count} words (entry is hidden); several per line is fine. Four letters of each word are enough.");
        println!("Or type 'scan' to read a SeedQR with the camera. Empty line = cancel.");
        // The phrase is built straight into a zeroizing buffer.
        let mut phrase = Zeroizing::new(String::new());
        let mut n_words = 0usize;
        let mut cancelled = false;
        let mut scanned = None;
        while n_words < count {
            let line = prompt_secret(&format!("  words {}-: ", n_words + 1));
            if line.is_empty() {
                cancelled = true;
                break;
            }
            if line.eq_ignore_ascii_case("scan") {
                match harden::scan_qr_with_zbarcam(&s.camera) {
                    Ok(text) => {
                        let text = Zeroizing::new(text);
                        match keygen::parse_standard_seedqr(&text) {
                            Ok(m) => {
                                scanned = Some(m);
                                break;
                            }
                            Err(e) => println!("  {e}"),
                        }
                    }
                    Err(e) => println!("  {e}"),
                }
                continue;
            }
            let mut resolved = Vec::new();
            let mut bad = Vec::new();
            for t in line.split_whitespace() {
                match keygen::resolve_bip39_word(t) {
                    Some(w) => resolved.push(w),
                    None => bad.push(t.to_string()),
                }
            }
            if !bad.is_empty() {
                println!("  Not BIP39 words (line ignored, retype it): {}", bad.join(" "));
                continue;
            }
            if n_words + resolved.len() > count {
                println!("  That is more than {count} words; line ignored.");
                continue;
            }
            for w in resolved {
                if n_words > 0 {
                    phrase.push(' ');
                }
                phrase.push_str(w);
                n_words += 1;
            }
        }
        if cancelled {
            return None;
        }
        if let Some(m) = scanned {
            break m;
        }
        match bip39::Mnemonic::parse_in(bip39::Language::English, phrase.as_str()) {
            Ok(m) => break m,
            Err(e) => println!("  These words do not form a valid seed ({e}). Start again."),
        }
    };
    print!("BIP39 passphrase (Enter for none; not shown): ");
    let _ = io::stdout().flush();
    let mut pass = match harden::read_line_noecho() {
        Ok(s) => s,
        Err(e) => {
            println!("Unable to read passphrase: {e}");
            return None;
        }
    };
    let end = pass.trim_end_matches(['\r', '\n']).len();
    pass.truncate(end);
    let w = Wallet::from_mnemonic(&mnemonic, &pass);
    println!("Seed loaded. Wallet fingerprint: {}", w.fingerprint());
    Some(w)
}

/// Read a frame typed line by line, pasted as an AS1 string, or scanned.
pub fn read_frame(s: &Session, what: &str) -> Option<Vec<u8>> {
    println!("Enter the {what}:");
    println!("  - type the words line by line, each line ending with its check word");
    println!("    (full words, or two letters per word: first and last letter)");
    println!("  - or paste/type the AS1... string, or type 'scan' for the camera");
    println!("  - empty line = cancel");
    let mut reader = TranscriptReader::new();
    loop {
        let label = match reader.total_lines() {
            Some(t) => format!("  line {}/{}: ", reader.next_line_number(), t),
            None => format!("  line {}: ", reader.next_line_number()),
        };
        let line = prompt(&label);
        if line.is_empty() {
            return None;
        }
        let text = if line.eq_ignore_ascii_case("scan") {
            match harden::scan_qr_with_zbarcam(&s.camera) {
                Ok(t) => t,
                Err(e) => {
                    println!("  {e}");
                    continue;
                }
            }
        } else {
            line
        };
        let compact: String = text.split_whitespace().collect();
        if compact.get(..3).is_some_and(|prefix| prefix.eq_ignore_ascii_case(frame::QR_PREFIX)) {
            match frame::parse_text(&compact) {
                Ok(f) => return Some(f),
                Err(e) => {
                    println!("  {e}");
                    continue;
                }
            }
        }
        match reader.push_line(&text) {
            Ok(LineResult::Done(f)) => return Some(f),
            Ok(LineResult::NeedMore { .. }) => {}
            Err(e) => println!("  {e}"),
        }
    }
}

/// Show a frame as a QR code first; words on request.
pub fn show_frame(frame: &[u8], title: &str) {
    let qr_text = to_qr_string(frame);
    let mut view = 'q';
    loop {
        clear();
        println!("{title}  ({} bytes)", frame.len());
        match view {
            'w' => print!("{}", render_transcript(frame, WordStyle::Full)),
            'm' => print!("{}", render_transcript(frame, WordStyle::Minimal)),
            't' => println!("{qr_text}"),
            _ => match qr::render_terminal(&qr_text) {
                Ok(q) => println!("{q}"),
                Err(e) => println!("{e}"),
            },
        }
        let a = prompt("[q] QR  [w] words  [m] two-letter words  [t] text  [Enter] done: ");
        match a.to_ascii_lowercase().chars().next() {
            None => return,
            Some(c) if "qwmt".contains(c) => view = c,
            _ => {}
        }
    }
}

fn sign_flow(s: &Session) -> Result<(), CodecError> {
    let Some(wallet) = load_wallet(s) else { return Ok(()) };
    loop {
        let Some(f) = read_frame(s, "signing request") else { return Ok(()) };
        let req = match SignRequest::decode(&f) {
            Ok(r) => r,
            Err(e) => {
                println!("  {e}");
                continue;
            }
        };
        let rv = match signer::review(&wallet, &req) {
            Ok(rv) => rv,
            Err(e) => {
                println!("  {e}");
                return Ok(());
            }
        };
        clear();
        println!("Check every line against the online computer and your own intent:\n");
        for l in &rv.summary {
            println!("{l}");
        }
        if !rv.warnings.is_empty() {
            println!();
            for w in &rv.warnings {
                println!("  WARNING: {w}");
            }
        }
        let need = if rv.warnings.is_empty() { "sign" } else { "sign anyway" };
        println!();
        let a = prompt(&format!("Type '{need}' to sign, anything else to cancel: "));
        if a != need {
            println!("Not signed.");
            pause("[Enter] ");
            return Ok(());
        }
        let sigs = signer::sign(&wallet, &req, &rv)?;
        show_frame(&encode_signatures(&sigs), "Signatures: scan or type these on the online computer");
        return Ok(());
    }
}

fn keygen_flow(_s: &Session) -> Result<(), CodecError> {
    let count = ask_word_count();
    println!("Entropy: the operating system's random generator, optionally mixed with dice.");
    println!("  Enter      use the system RNG only");
    println!("  r          also mix in dice rolls (safe even if the dice are biased)");
    println!("  d          dice ONLY, verifiable elsewhere with sha256 (needs {}+ rolls)", keygen::min_rolls(count));
    let mode = prompt("> ").to_ascii_lowercase();
    let entropy = if mode == "r" || mode == "d" {
        let mut rolls = Zeroizing::new(String::new());
        let want = if mode == "d" { keygen::min_rolls(count) } else { 1 };
        while rolls.len() < want || mode == "r" {
            let line = prompt_secret(&format!("  rolls so far {} (Enter when done): ", rolls.len()));
            if line.is_empty() {
                if rolls.len() >= want {
                    break;
                }
                println!("  need at least {want} rolls");
                continue;
            }
            match keygen::clean_rolls(&line) {
                Ok(mut r) => {
                    rolls.push_str(&r);
                    r.zeroize();
                },
                Err(e) => println!("  {e}"),
            }
        }
        if mode == "d" {
            keygen::dice_only(&rolls, count)?
        } else {
            keygen::mixed(&*keygen::os_entropy()?, &rolls, count)?
        }
    } else {
        keygen::mixed(&*keygen::os_entropy()?, "", count)?
    };
    let m = keygen::mnemonic(&entropy)?;
    let words: Vec<&str> = m.words().collect();
    clear();
    println!("Write these {count} words down, in order. They are the only copy.\n");
    let rows = count / 4;
    for r in 0..rows {
        for c in 0..4 {
            let i = c * rows + r;
            print!("  {:>2}. {:<10}", i + 1, words[i]);
        }
        println!();
    }
    let w = Wallet::from_mnemonic(&m, "");
    println!("\nWallet fingerprint (no passphrase): {}", w.fingerprint());
    if prompt("\n[s] also show a Standard SeedQR to copy by hand, [Enter] continue: ").eq_ignore_ascii_case("s") {
        let digits = keygen::standard_seedqr(&m);
        clear();
        print!("{}", qr::render_seedqr_terminal(&digits)?);
        pause("[Enter] ");
    }
    clear();
    println!("Verify your paper or steel backup by re-entering all {count} words in order.");
    println!("The seed is hidden. A mismatched or missing word blocks the watch-only export.");
    for (i, expected) in words.iter().enumerate() {
        let typed = prompt_secret(&format!("  word #{}: ", i + 1));
        if typed.is_empty() {
            return Err(CodecError("Backup verification cancelled; watch-only account not exported".into()));
        }
        if !backup_word_matches(expected, &typed) {
            return Err(CodecError(format!(
                "Backup word #{} did not match; check your physical copy and restart verification",
                i + 1
            )));
        }
    }
    println!("All {count} backup words confirmed.");
    if prompt("Show the watch-only account for the online wallet now? [Y/n] ").eq_ignore_ascii_case("n") {
        return Ok(());
    }
    let net = ask_network();
    show_first_receive_address(&w, net, 0);
    show_frame(&w.account_export(net, 0).encode(), "Watch-only account 0: import on the online computer");
    Ok(())
}

fn export_flow(s: &Session) -> Result<(), CodecError> {
    let Some(w) = load_wallet(s) else { return Ok(()) };
    let net = ask_network();
    let account = loop {
        let a = prompt("Account number [0]: ");
        if a.is_empty() {
            break 0;
        }
        match a.parse::<u32>() {
            Ok(n) if n < 1 << 31 => break n,
            _ => println!("  not a valid account number"),
        }
    };
    show_first_receive_address(&w, net, account);
    show_frame(&w.account_export(net, account).encode(), &format!("Watch-only account {account}"));
    Ok(())
}

/// What this boot can vouch for, shown on the live image's main menu. Under
/// Secure Boot the command line is the one sealed in the signed UKI, and the
/// initramfs has already refused to continue unless the mounted system image
/// verified against this root hash.
fn boot_status() -> String {
    let sb = std::fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        .ok()
        .and_then(|v| v.get(4).copied());
    let root = std::fs::read_to_string("/proc/cmdline").ok().and_then(|c| {
        c.split_whitespace()
            .find_map(|p| p.strip_prefix("dm-verity-root-hash=filesystem.squashfs:").map(String::from))
    });
    let sb_text = match sb {
        Some(1) => "Secure Boot ON",
        Some(_) => "Secure Boot OFF: this boot was NOT verified",
        None => "Secure Boot state unknown",
    };
    match root {
        Some(r) => format!("{sb_text}  |  system image root {}", &r[..r.len().min(16)]),
        None => format!("{sb_text}  |  system image NOT verified"),
    }
}

pub fn menu(s: &Session) -> i32 {
    for note in harden::harden() {
        if s.live {
            println!("note: {note}");
        }
    }
    loop {
        clear();
        println!("airsign {}  offline signer", env!("CARGO_PKG_VERSION"));
        if s.live {
            println!("{}", boot_status());
        }
        println!();
        println!("  1  Sign a transaction");
        println!("  2  Create a new seed");
        println!("  3  Show the watch-only account for a seed");
        println!("  4  {}", if s.live { "Shut down (memory is wiped)" } else { "Quit" });
        let r = match prompt("\n> ").as_str() {
            "1" => sign_flow(s),
            "2" => keygen_flow(s),
            "3" => export_flow(s),
            "4" | "q" => return 0,
            _ => Ok(()),
        };
        if let Err(e) = r {
            println!("error: {e}");
            pause("[Enter] ");
        }
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn every_backup_word_must_match() {
        let m = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let words: Vec<&str> = m.words().collect();
        assert!(words.iter().all(|w| backup_word_matches(w, &w[..4])));
        for n in 0..words.len() {
            let mut supplied = words.clone();
            supplied[n] = "zoo";
            assert!(!supplied.iter().zip(&words).all(|(given, expected)| backup_word_matches(expected, given)));
        }
    }
}
