//! Command-line interface for the fully local Shamir Secret Sharing tool.
//!
//! Secrets are read from a file or standard input — **never** from a command
//! line argument, because `argv` is visible to other local processes via
//! `ps`/`/proc`. Log output contains share indices, paths and sizes only;
//! neither secret bytes nor share payloads are ever printed.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use local_shamir::{combine, split, Share, SssError, MAX_SECRET_LEN};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), SssError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_help();
        return Ok(());
    }
    if matches!(args[0].as_str(), "-V" | "--version") {
        println!("local-shamir {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    match args[0].as_str() {
        "split" => cmd_split(&args[1..]),
        "combine" => cmd_combine(&args[1..]),
        other => {
            eprintln!("unknown subcommand '{other}'\n");
            print_help();
            Err(SssError::InvalidParameters("unknown subcommand".into()))
        }
    }
}

fn print_help() {
    let help = "\
local-shamir — fully local Shamir Secret Sharing over GF(2^8)

USAGE:
    local-shamir split   -k THRESHOLD -n SHARES  -s SECRET_FILE -o OUT_DIR
    local-shamir combine  -o SECRET_OUT           SHARE_FILE [SHARE_FILE ...]

SPLIT:
    -k, --threshold <K>         shares required to recover (>= 2, <= n)
    -n, --shares <N>            total shares to create (<= 255)
    -s, --secret-file <PATH>    file holding the secret bytes, or '-' for stdin
                                (never pass the secret on the command line)
    -o, --out-dir <DIR>         directory for share-01.bin .. share-NN.bin
                                (created if missing; must not contain
                                 share files that would be overwritten)

COMBINE:
    -o, --out <PATH>            write recovered secret here ('-' for stdout)
    SHARE_FILE ...              at least K share files (extra files ignored
                                once K consistent shares are available)

All processing is local: no network, KMS, Vault or external key service.
Secrets and share payloads are never written to logs.
";
    println!("{help}");
}

/// Tiny flag parser: `--name value` / `--name=value` / short aliases.
struct Args<'a> {
    tokens: &'a [String],
}

impl<'a> Args<'a> {
    fn value(&mut self, names: &[&str]) -> Result<Option<String>, SssError> {
        for (i, tok) in self.tokens.iter().enumerate() {
            for name in names {
                if let Some(rest) = tok.strip_prefix(&format!("{name}=")) {
                    return Ok(Some(rest.to_string()));
                }
                if tok == name {
                    return self.tokens.get(i + 1).cloned().ok_or_else(|| {
                        SssError::InvalidParameters(format!("missing value for {name}"))
                    }).map(Some);
                }
            }
        }
        Ok(None)
    }

    fn positionals(&self, names: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        let mut skip_next = false;
        for tok in self.tokens {
            if skip_next {
                skip_next = false;
                continue;
            }
            if names.iter().any(|name| tok == *name) {
                skip_next = true; // the following token is the value
                continue;
            }
            if names.iter().any(|name| tok.starts_with(&format!("{name}="))) {
                continue;
            }
            out.push(tok.clone());
        }
        out
    }
}

fn parse_u8(s: &str, what: &str) -> Result<u8, SssError> {
    s.parse::<u8>()
        .map_err(|_| SssError::InvalidParameters(format!("{what} must be a number 0..=255, got '{s}'")))
}

fn read_secret(path: &str) -> Result<Vec<u8>, SssError> {
    let mut buf = Vec::new();
    if path == "-" {
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| SssError::Io(format!("reading secret from stdin: {e}")))?;
    } else {
        buf = fs::read(path).map_err(|e| SssError::Io(format!("reading secret file {path}: {e}")))?;
    }
    if buf.len() > MAX_SECRET_LEN {
        return Err(SssError::SecretTooLong(buf.len()));
    }
    Ok(buf)
}

fn cmd_split(tokens: &[String]) -> Result<(), SssError> {
    let mut args = Args { tokens };
    let k = args
        .value(&["-k", "--threshold"])?
        .ok_or_else(|| SssError::InvalidParameters("split requires -k/--threshold".into()))
        .and_then(|v| parse_u8(&v, "threshold k"))?;
    let n = args
        .value(&["-n", "--shares"])?
        .ok_or_else(|| SssError::InvalidParameters("split requires -n/--shares".into()))
        .and_then(|v| parse_u8(&v, "share count n"))?;
    let secret_path = args
        .value(&["-s", "--secret-file"])?
        .ok_or_else(|| SssError::InvalidParameters("split requires -s/--secret-file".into()))?;
    let out_dir = args
        .value(&["-o", "--out-dir"])?
        .ok_or_else(|| SssError::InvalidParameters("split requires -o/--out-dir".into()))?;

    let secret = read_secret(&secret_path)?;
    eprintln!(
        "splitting {} secret bytes into {n} shares (threshold {k})",
        secret.len()
    );

    let shares = split(&secret, k, n)?;

    let dir = PathBuf::from(&out_dir);
    fs::create_dir_all(&dir)
        .map_err(|e| SssError::Io(format!("creating output directory {}: {e}", dir.display())))?;

    // Refuse to silently overwrite existing share files.
    for s in &shares {
        let p = share_path(&dir, s.header.index, n);
        if p.exists() {
            return Err(SssError::Io(format!(
                "{} already exists; move it aside before splitting",
                p.display()
            )));
        }
    }
    for s in &shares {
        let p = share_path(&dir, s.header.index, n);
        let bytes = s.to_bytes();
        write_file(&p, &bytes)?;
        // Log metadata only: index and path. No payload, no secret.
        eprintln!("wrote {} (share index {}, {} bytes)", p.display(), s.header.index, bytes.len());
    }

    eprintln!("done: distribute the {n} share files through separate channels;");
    eprintln!("      any {k} of them reconstruct the secret.");
    Ok(())
}

fn share_path(dir: &Path, index: u8, n: u8) -> PathBuf {
    // Decimal width of n, computed with integer division only; zero-pad to at
    // least two digits so shares sort naturally (share-01.bin, ..., share-10.bin).
    let mut width = 1usize;
    let mut x = n;
    while x >= 10 {
        x /= 10;
        width += 1;
    }
    if width < 2 {
        width = 2;
    }
    dir.join(format!("share-{:0width$}.bin", index, width = width))
}

fn cmd_combine(tokens: &[String]) -> Result<(), SssError> {
    let known = ["-o", "--out"];
    let mut args = Args { tokens };
    let out_path = args
        .value(&known)?
        .ok_or_else(|| SssError::InvalidParameters("combine requires -o/--out".into()))?;
    let files = args.positionals(&known);
    if files.is_empty() {
        return Err(SssError::InvalidParameters(
            "combine requires at least one share file".into(),
        ));
    }

    eprintln!("reading {} share file(s)", files.len());
    let mut shares: Vec<Share> = Vec::with_capacity(files.len());
    for path in &files {
        let data = fs::read(path)
            .map_err(|e| SssError::Io(format!("reading share file {path}: {e}")))?;
        let share = Share::from_bytes(&data).map_err(|e| {
            // Wrap with file context while preserving the typed error kind.
            match e {
                SssError::CorruptedShare { index, reason } => SssError::CorruptedShare {
                    index,
                    reason: format!("{path}: {reason}"),
                },
                other => other,
            }
        })?;
        eprintln!("  {path}: index {}", share.header.index);
        shares.push(share);
    }

    let recovered = combine(&shares)?;
    eprintln!("recovered {} secret bytes", recovered.len());

    if out_path == "-" {
        let stdout = io::stdout();
        stdout
            .lock()
            .write_all(&recovered)
            .map_err(|e| SssError::Io(format!("writing secret to stdout: {e}")))?;
    } else {
        write_file(Path::new(&out_path), &recovered)?;
        eprintln!("wrote secret to {out_path}");
    }
    Ok(())
}

fn write_file(path: &Path, data: &[u8]) -> Result<(), SssError> {
    // Restrictive permissions: shares and recovered secrets are sensitive.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| SssError::Io(format!("writing {}: {e}", path.display())))
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data).map_err(|e| SssError::Io(format!("writing {}: {e}", path.display())))
    }
}
