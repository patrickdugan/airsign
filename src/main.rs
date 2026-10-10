use std::collections::HashMap;
use std::io::Read;
use std::process::ExitCode;
use std::str::FromStr;

use airsign::codec::{render_transcript, CodecError, WordStyle};
use airsign::combine::combine;
use airsign::frame::{self, decode_signatures, encode_signatures, parse_network, to_qr_string, Account, Kind};
use airsign::request::{Dest, SignRequest};
use airsign::signer::{self, btc, Wallet};
use airsign::{keygen, qr, ui};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use zeroize::Zeroizing;

const USAGE: &str = "\
airsign - amnesic air-gapped signer for BIP86 taproot wallets

Offline machine:
  airsign [menu] [--live] [--camera /dev/video0]   interactive console
  airsign account  --mnemonic-file F [--passphrase-file F] --network N [--account N]
  airsign sign     --mnemonic-file F [--passphrase-file F] --request R [--yes]
  airsign keygen   --words 12|24 [--dice ROLLS | --dice-only ROLLS]

Online machine (with a watch-only wallet such as Bitcoin Core):
  airsign descriptors ACCOUNT          print descriptors + importdescriptors JSON
  airsign request  --network N --psbt P
  airsign combine  --psbt P --signatures S [--psbt-out FILE]
  airsign inspect  FRAME
  airsign show     FRAME [--format words|minimal|as1|qr] [--pbm FILE]

Frames (ACCOUNT, R, S, FRAME) are an AS1... string or a word transcript.
Any value can be @FILE to read it from a file, or - for stdin.
Output format for commands that emit a frame: --format all|as1|words|minimal|qr
";

type Res<T> = Result<T, CodecError>;

fn fail<T>(msg: impl Into<String>) -> Res<T> {
    Err(CodecError(msg.into()))
}

struct Args {
    flags: HashMap<String, Option<String>>,
    positional: Vec<String>,
}

const VALUE_FLAGS: &[&str] = &[
    "mnemonic-file", "passphrase-file", "network", "account", "request", "psbt", "signatures", "psbt-out",
    "pbm", "words", "dice", "dice-only", "format", "camera",
];

impl Args {
    fn parse(raw: &[String]) -> Res<Self> {
        let mut flags = HashMap::new();
        let mut positional = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            let a = &raw[i];
            if let Some(name) = a.strip_prefix("--") {
                if VALUE_FLAGS.contains(&name) {
                    let v = raw.get(i + 1).ok_or_else(|| CodecError(format!("--{name} needs a value")))?;
                    flags.insert(name.to_string(), Some(v.clone()));
                    i += 2;
                    continue;
                }
                flags.insert(name.to_string(), None);
            } else {
                positional.push(a.clone());
            }
            i += 1;
        }
        Ok(Args { flags, positional })
    }

    fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }

    fn get(&self, k: &str) -> Option<&str> {
        self.flags.get(k).and_then(|v| v.as_deref())
    }

    fn need(&self, k: &str) -> Res<&str> {
        self.get(k).ok_or_else(|| CodecError(format!("missing --{k}")))
    }
}

/// "@path" reads a file, "-" reads stdin, anything else is the value itself.
fn load(v: &str) -> Res<String> {
    if v == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| CodecError(e.to_string()))?;
        return Ok(s);
    }
    if let Some(p) = v.strip_prefix('@') {
        return std::fs::read_to_string(p).map_err(|e| CodecError(format!("{p}: {e}")));
    }
    Ok(v.to_string())
}

fn load_wallet(a: &Args) -> Res<Wallet> {
    let path = a.need("mnemonic-file")?;
    let words = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| CodecError(format!("{path}: {e}")))?);
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, words.trim())
        .map_err(|e| CodecError(format!("mnemonic: {e}")))?;
    let pass = match a.get("passphrase-file") {
        Some(p) => Zeroizing::new(
            std::fs::read_to_string(p).map_err(|e| CodecError(format!("{p}: {e}")))?.trim_end_matches(['\r', '\n']).to_string(),
        ),
        None => Zeroizing::new(String::new()),
    };
    Ok(Wallet::from_mnemonic(&m, &pass))
}

fn emit(frame: &[u8], a: &Args) -> Res<()> {
    let qr_text = to_qr_string(frame);
    match a.get("format").unwrap_or("all") {
        "as1" => println!("{qr_text}"),
        "words" => print!("{}", render_transcript(frame, WordStyle::Full)),
        "minimal" => print!("{}", render_transcript(frame, WordStyle::Minimal)),
        "qr" => println!("{}", qr::render_terminal(&qr_text)?),
        "all" => {
            let lines = airsign::codec::transcript_lines(frame).len();
            println!(
                "# {} bytes; {} words in {} lines; {} QR characters (QR version {})",
                frame.len(),
                lines + airsign::codec::transcript_lines(frame).iter().map(|l| l.len() - 1).sum::<usize>(),
                lines,
                qr_text.len(),
                qr::version_of(&qr_text).unwrap_or(0)
            );
            print!("{}", render_transcript(frame, WordStyle::Full));
            println!();
            print!("{}", render_transcript(frame, WordStyle::Minimal));
            println!();
            println!("{qr_text}");
        }
        f => return fail(format!("unknown --format {f}")),
    }
    Ok(())
}

fn print_request(req: &SignRequest) {
    eprintln!("Request for wallet {} account {} ({:?})", req.master_fp, req.account, req.network);
    eprintln!("  inputs: {}  total {} BTC", req.inputs.len(), btc(req.total_in()));
    for (n, o) in req.outputs.iter().enumerate() {
        match &o.dest {
            Dest::Own(p) => eprintln!("  #{n} {} BTC to own {}", btc(o.amount), p.describe(req.network, req.account)),
            Dest::Script(s) => eprintln!("  #{n} {} BTC to {}", btc(o.amount), signer::describe_script(s, req.network).0),
        }
    }
    eprintln!("  fee {} BTC", btc(req.total_in().saturating_sub(req.total_out())));
}

fn run(raw: Vec<String>) -> Res<()> {
    let cmd = raw.first().map(String::as_str).unwrap_or("menu");
    let a = Args::parse(raw.get(1..).unwrap_or(&[]))?;
    match cmd {
        "menu" | "--live" => {
            let s = ui::Session {
                camera: a.get("camera").unwrap_or("/dev/video0").to_string(),
                live: a.has("live") || cmd == "--live",
            };
            std::process::exit(ui::menu(&s));
        }
        "help" | "--help" | "-h" => print!("{USAGE}"),
        "--version" | "version" => println!("airsign {}", env!("CARGO_PKG_VERSION")),
        "account" => {
            let w = load_wallet(&a)?;
            let net = parse_network(a.need("network")?)?;
            let account: u32 = a.get("account").unwrap_or("0").parse().map_err(|_| CodecError("bad --account".into()))?;
            if account >= 1 << 31 {
                return fail("account must be below 2^31");
            }
            eprintln!("wallet {} account {account}", w.fingerprint());
            emit(&w.account_export(net, account).encode(), &a)?;
        }
        "sign" => {
            for n in airsign::harden::harden() {
                eprintln!("note: {n}");
            }
            let w = load_wallet(&a)?;
            let req = SignRequest::decode(&frame::parse_text(&load(a.need("request")?)?)?)?;
            let rv = signer::review(&w, &req)?;
            for l in &rv.summary {
                eprintln!("{l}");
            }
            for x in &rv.warnings {
                eprintln!("  WARNING: {x}");
            }
            if !a.has("yes") {
                eprint!("Type 'sign' to sign: ");
                let mut s = String::new();
                std::io::stdin().read_line(&mut s).map_err(|e| CodecError(e.to_string()))?;
                if s.trim() != "sign" {
                    return fail("not signed");
                }
            }
            let sigs = signer::sign(&w, &req, &rv)?;
            emit(&encode_signatures(&sigs), &a)?;
        }
        "keygen" => {
            let words: usize = a.get("words").unwrap_or("24").parse().map_err(|_| CodecError("bad --words".into()))?;
            let entropy = if let Some(r) = a.get("dice-only") {
                keygen::dice_only(&keygen::clean_rolls(&load(r)?)?, words)?
            } else {
                let rolls = match a.get("dice") {
                    Some(r) => keygen::clean_rolls(&load(r)?)?,
                    None => String::new(),
                };
                keygen::mixed(&*keygen::os_entropy()?, &rolls, words)?
            };
            let m = keygen::mnemonic(&entropy)?;
            println!("{m}");
            eprintln!("fingerprint {}", Wallet::from_mnemonic(&m, "").fingerprint());
        }
        "descriptors" => {
            let text = load(a.positional.first().ok_or_else(|| CodecError("give the account frame".into()))?)?;
            let acct = Account::decode(&frame::parse_text(&text)?)?;
            let (recv, change) = acct.descriptors();
            println!("{recv}\n{change}");
            println!(
                "[{{\"desc\":\"{recv}\",\"active\":true,\"internal\":false,\"timestamp\":\"now\",\"range\":[0,999]}},\
                 {{\"desc\":\"{change}\",\"active\":true,\"internal\":true,\"timestamp\":\"now\",\"range\":[0,999]}}]"
            );
        }
        "request" => {
            let net = parse_network(a.need("network")?)?;
            let psbt = Psbt::from_str(load(a.need("psbt")?)?.trim()).map_err(|e| CodecError(format!("PSBT: {e}")))?;
            let secp = Secp256k1::verification_only();
            let req = SignRequest::from_psbt(&secp, &psbt, net)?;
            print_request(&req);
            emit(&req.encode(), &a)?;
        }
        "combine" => {
            let mut psbt =
                Psbt::from_str(load(a.need("psbt")?)?.trim()).map_err(|e| CodecError(format!("PSBT: {e}")))?;
            let sigs = decode_signatures(&frame::parse_text(&load(a.need("signatures")?)?)?)?;
            let tx = combine(&mut psbt, &sigs)?;
            if let Some(p) = a.get("psbt-out") {
                std::fs::write(p, psbt.to_string()).map_err(|e| CodecError(format!("{p}: {e}")))?;
            }
            println!("{}", serialize_hex(&tx));
            eprintln!("txid {}", tx.compute_txid());
        }
        "inspect" => {
            let f = frame::parse_text(&load(a.positional.first().ok_or_else(|| CodecError("give a frame".into()))?)?)?;
            match frame::open(&f)?.0 {
                Kind::Account => {
                    let acct = Account::decode(&f)?;
                    println!("watch-only account {}{}", acct.origin(), acct.xpub());
                }
                Kind::Request => {
                    let r = SignRequest::decode(&f)?;
                    print_request(&r);
                    println!("{r:#?}");
                }
                Kind::Signatures => {
                    for (k, s) in decode_signatures(&f)?.iter().enumerate() {
                        println!("input {k}: {s}");
                    }
                }
            }
        }
        "show" => {
            let f = frame::parse_text(&load(a.positional.first().ok_or_else(|| CodecError("give a frame".into()))?)?)?;
            frame::open(&f)?;
            if let Some(p) = a.get("pbm") {
                std::fs::write(p, qr::pbm(&to_qr_string(&f), 6)?).map_err(|e| CodecError(format!("{p}: {e}")))?;
            } else {
                emit(&f, &a)?;
            }
        }
        #[cfg(feature = "dev")]
        "dev-private-descriptors" => {
            let w = load_wallet(&a)?;
            let net = parse_network(a.need("network")?)?;
            let (r, c) = w.dev_private_descriptors(net, 0);
            println!("{r}\n{c}");
        }
        other => return fail(format!("unknown command '{other}'\n\n{USAGE}")),
    }
    Ok(())
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    match run(raw) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
