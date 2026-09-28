//! Command-line front-end for local-sss.
//!
//! Usage:
//!   sss split   -k <K> -n <N> --secret <FILE|-> --out-dir <DIR>
//!   sss combine --out <FILE|-> [--in-dir <DIR> | <SHARE-FILE>...]
//!   sss inspect <SHARE-FILE>...
//!
//! The original secret is never written to logs or stderr. On success the
//! split command prints only the paths of the share files it created.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use local_sss::{combine_shares, split_secret, OsRng, SssError, Share, MAX_SECRET_LEN};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(msg)) => {
            eprintln!("usage error: {msg}");
            eprintln!();
            print_help(&mut std::io::stderr());
            ExitCode::from(2)
        }
        Err(CliError::Run(e)) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
        Err(CliError::Io(e)) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

enum CliError {
    Usage(String),
    Run(SssError),
    Io(std::io::Error),
}

impl From<SssError> for CliError {
    fn from(e: SssError) -> Self {
        CliError::Run(e)
    }
}
impl From<String> for CliError {
    /// Flag-parser errors are usage errors.
    fn from(e: String) -> Self {
        CliError::Usage(e)
    }
}
impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

fn run(args: &[String]) -> std::result::Result<(), CliError> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_help(&mut std::io::stdout());
        return Ok(());
    }
    match args[0].as_str() {
        "split" => cmd_split(&args[1..]),
        "combine" => cmd_combine(&args[1..]),
        "inspect" => cmd_inspect(&args[1..]),
        other => Err(CliError::Usage(format!("unknown command '{other}'"))),
    }
}

/// Small flag parser: supports `--flag value`, `--flag=value` and booleans.
struct Flags<'a> {
    args: &'a [String],
}

impl<'a> Flags<'a> {
    fn get(&self, name: &str) -> std::result::Result<Option<String>, String> {
        // Accepts both `--name value` / `--name=value` and, for single
        // character names, `-n value` / `-n=value` (e.g. -k, -n).
        let long = format!("--{name}");
        let short_eq = (name.len() == 1).then(|| format!("-{name}="));
        let short = (name.len() == 1).then(|| format!("-{name}"));
        let mut iter = self.args.iter();
        let mut value: Option<String> = None;
        macro_rules! assign {
            ($v:expr, $flag:expr) => {
                if value.is_some() {
                    return Err(format!("{} specified more than once", $flag));
                }
                value = Some($v);
            };
        }
        while let Some(a) = iter.next() {
            if let Some(rest) = a.strip_prefix(&format!("{long}=")) {
                assign!(rest.to_string(), &long);
            } else if a == &long {
                let v = iter
                    .next()
                    .ok_or_else(|| format!("{long} requires a value"))?;
                assign!(v.clone(), &long);
            } else if let Some(se) = short_eq.as_deref() {
                // Short forms, only for single-character names: -x=value / -x value
                if let Some(rest) = a.strip_prefix(se) {
                    assign!(rest.to_string(), se);
                } else if Some(a.as_str()) == short.as_deref() {
                    let v = iter
                        .next()
                        .ok_or_else(|| format!("{a} requires a value"))?;
                    assign!(v.clone(), a.as_str());
                }
            }
        }
        Ok(value)
    }

    fn positionals(&self, names: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        let mut iter = self.args.iter();
        while let Some(a) = iter.next() {
            if a.starts_with('-') {
                // Skip the value following either "--flag"/"-f" (no '='),
                // when the flag is one of the known value-taking ones.
                if !a.contains('=')
                    && names.iter().any(|n| {
                        a == &format!("--{n}") || (n.len() == 1 && a == &format!("-{n}"))
                    })
                {
                    iter.next();
                }
            } else {
                out.push(a.clone());
            }
        }
        out
    }
}

fn parse_u8(s: &str, what: &str) -> std::result::Result<u8, CliError> {
    s.parse::<u8>()
        .map_err(|_| CliError::Usage(format!("{what} must be a number 1..=255, got '{s}'")))
}

fn cmd_split(args: &[String]) -> std::result::Result<(), CliError> {
    let flags = Flags { args };
    let k = flags
        .get("k")?
        .map(|v| parse_u8(&v, "threshold k"))
        .transpose()?
        .ok_or_else(|| CliError::Usage("--k is required".into()))?;
    let n = flags
        .get("n")?
        .map(|v| parse_u8(&v, "share count n"))
        .transpose()?
        .ok_or_else(|| CliError::Usage("--n is required".into()))?;
    let secret_path = flags
        .get("secret")?
        .ok_or_else(|| CliError::Usage("--secret <FILE|-> is required".into()))?;
    let out_dir = PathBuf::from(
        flags
            .get("out-dir")?
            .ok_or_else(|| CliError::Usage("--out-dir <DIR> is required".into()))?,
    );

    let mut secret = Vec::new();
    if secret_path == "-" {
        std::io::stdin().read_to_end(&mut secret)?;
    } else {
        secret = fs::read(&secret_path)?;
    }
    if secret.len() > MAX_SECRET_LEN {
        return Err(CliError::Run(SssError::SecretTooLarge(secret.len())));
    }

    let mut rng = OsRng::new();
    let shares = split_secret(&secret, k, n, &mut rng)?;

    fs::create_dir_all(&out_dir)?;
    for s in &shares {
        let path = out_dir.join(format!("share-{:03}.bin", s.index));
        // 0600: shares are sensitive material
        write_secret_file(&path, &s.to_bytes())?;
        println!("{}", path.display());
    }
    eprintln!(
        "split complete: {n} shares written to {}; any {k} reconstruct.",
        out_dir.display()
    );
    Ok(())
}

#[cfg(unix)]
fn write_secret_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}

fn cmd_combine(args: &[String]) -> std::result::Result<(), CliError> {
    let flags = Flags { args };
    let out = flags
        .get("out")?
        .ok_or_else(|| CliError::Usage("--out <FILE|-> is required".into()))?;
    let in_dir = flags.get("in-dir")?;

    let mut paths: Vec<PathBuf> = match in_dir {
        Some(dir) => {
            let mut v = Vec::new();
            for entry in fs::read_dir(&dir)? {
                let p = entry?.path();
                if p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("share-") && n.ends_with(".bin"))
                {
                    v.push(p);
                }
            }
            v.sort();
            v
        }
        None => flags
            .positionals(&["out", "in-dir", "k", "n", "secret"])
            .into_iter().map(PathBuf::from)
            .collect(),
    };
    if paths.is_empty() {
        return Err(CliError::Usage(
            "provide share files as positional arguments or via --in-dir <DIR>".into(),
        ));
    }
    paths.sort();

    let mut shares = Vec::with_capacity(paths.len());
    for p in &paths {
        let data = fs::read(p)?;
        // Parse (and checksum-verify) each file. Errors carry the path so
        // corrupt files are easy to locate; share contents are never logged.
        // Error displays by construction carry only structural metadata
        // (bad magic, version, length, checksum status), never share/secret
        // bytes, so including the detail here is safe and aids diagnosis.
        let share = Share::from_bytes(&data).map_err(|e| {
            CliError::Run(SssError::MalformedShare(format!("{}: {e}", p.display())))
        })?;
        shares.push(share);
    }

    let secret = combine_shares(&shares)?;

    if out == "-" {
        std::io::stdout().write_all(secret.as_slice())?;
    } else {
        write_secret_file(Path::new(&out), secret.as_slice())?;
        eprintln!("reconstructed {} bytes -> {}", secret.len(), out);
    }
    Ok(())
}

fn cmd_inspect(args: &[String]) -> std::result::Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError::Usage("inspect requires at least one share file".into()));
    }
    for arg in args {
        let data = fs::read(arg)?;
        match Share::from_bytes(&data) {
            Ok(s) => {
                let sid_prefix: String = s.session_id[..4].iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "{arg}: version={} k={} n={} index={} data_bytes={} session={sid_prefix}…  OK",
                    s.version,
                    s.threshold,
                    s.n,
                    s.index,
                    s.y.len()
                );
            }
            Err(e) => {
                println!("{arg}: INVALID ({e})");
            }
        }
    }
    Ok(())
}

fn print_help<W: Write>(w: &mut W) {
    let _ = writeln!(
        w,
        "local-sss — local Shamir Secret Sharing over GF(2^8)\n\
         \n\
         USAGE:\n\
           sss split   -k <K> -n <N> --secret <FILE|-> --out-dir <DIR>\n\
               split the secret file ('-' = stdin) into N shares under {MAX} max size,\n\
               writing share-001.bin … share-NNN.bin (mode 0600).\n\
           sss combine --out <FILE|-> (--in-dir <DIR> | <SHARE-FILE>...)\n\
               reconstruct from >= K shares ('-' = stdout). Refuses below threshold.\n\
           sss inspect <SHARE-FILE>...\n\
               show metadata and integrity status without revealing share data.\n\
         \n\
         CONSTRAINTS: 1 <= K <= N <= 255, secret <= {MAX} bytes (64 KiB).\n\
         Everything runs locally; no network or key service is contacted.",
        MAX = MAX_SECRET_LEN
    );
}

