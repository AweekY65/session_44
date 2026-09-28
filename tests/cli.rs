//! End-to-end tests driving the `sss` binary through the filesystem.
//! Covers: split/combine over the CLI, arbitrary share subsets, missing
//! shares, tampered files, binary data and wrong-version files.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_sss"))
}

fn run(args: &[&str]) -> (std::process::Output, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn sss binary");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out, stdout, stderr)
}

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "local-sss-it-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_split_and_combine_text_secret() {
    let dir = tmp_dir("text");
    let secret = dir.join("secret.txt");
    let shares_dir = dir.join("shares");
    let recovered = dir.join("out.bin");
    fs::write(&secret, b"the quick brown fox").unwrap();

    let (out, stdout, _) = run(&[
        "split",
        "-k",
        "3",
        "-n",
        "5",
        "--secret",
        secret.to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "split failed: {stdout}");
    for i in 1..=5 {
        let p = shares_dir.join(format!("share-{i:03}.bin"));
        assert!(p.exists(), "missing {p:?}");
    }

    let (out, _, stderr) = run(&[
        "combine",
        "--in-dir",
        shares_dir.to_str().unwrap(),
        "--out",
        recovered.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "combine failed: {stderr}");
    assert_eq!(fs::read(&recovered).unwrap(), b"the quick brown fox");
}

#[test]
fn cli_binary_secret_and_arbitrary_subset() {
    let dir = tmp_dir("bin");
    let secret: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let secret_path = dir.join("secret.bin");
    fs::write(&secret_path, &secret).unwrap();

    let shares_dir = dir.join("shares");
    let (out, _, err) = run(&[
        "split",
        "-k",
        "4",
        "-n",
        "6",
        "--secret",
        secret_path.to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "split failed: {err}");

    // Pick shares 1,3,5,6 (an arbitrary 4-of-6 quorum).
    let subset = dir.join("subset");
    fs::create_dir_all(&subset).unwrap();
    for i in [1u8, 3, 5, 6] {
        fs::copy(
            shares_dir.join(format!("share-{i:03}.bin")),
            subset.join(format!("share-{i:03}.bin")),
        )
        .unwrap();
    }

    let recovered = dir.join("out.bin");
    let (out, _, err) = run(&[
        "combine",
        "--in-dir",
        subset.to_str().unwrap(),
        "--out",
        recovered.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "subset combine failed: {err}");
    assert_eq!(fs::read(&recovered).unwrap(), secret);
}

#[test]
fn cli_stdio_roundtrip_and_stdin_secret_not_leaked() {
    let dir = tmp_dir("stdio");
    let shares_dir = dir.join("shares");
    let secret = b"\x00\x01\x02\xff\xfe binary via stdin \x7f";

    let mut child = Command::new(bin())
        .args([
            "split",
            "-k",
            "2",
            "-n",
            "3",
            "--secret",
            "-",
            "--out-dir",
            shares_dir.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(secret).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // the raw secret must not appear in the tool's diagnostics
    assert!(!stderr.contains("binary via stdin"));

    // combine to stdout from explicit positional paths; must keep raw bytes,
    // so do not route stdout through a lossy UTF-8 conversion.
    let paths: Vec<String> = [1u8, 3]
        .iter()
        .map(|i| shares_dir.join(format!("share-{i:03}.bin")).to_string_lossy().into_owned())
        .collect();
    let mut cmd = Command::new(bin());
    cmd.args(["combine", "--out", "-"]);
    for p in &paths {
        cmd.arg(p);
    }
    let combined = cmd.output().expect("failed to spawn sss combine");
    assert!(combined.status.success());
    assert_eq!(combined.stdout.as_slice(), secret);
}

#[test]
fn cli_below_threshold_refuses_and_exits_nonzero() {
    let dir = tmp_dir("below");
    fs::write(dir.join("s"), b"need 3").unwrap();
    let shares_dir = dir.join("shares");
    run(&[
        "split",
        "-k",
        "3",
        "-n",
        "5",
        "--secret",
        dir.join("s").to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);

    let subset = dir.join("two");
    fs::create_dir_all(&subset).unwrap();
    for i in [2u8, 4] {
        fs::copy(
            shares_dir.join(format!("share-{i:03}.bin")),
            subset.join(format!("share-{i:03}.bin")),
        )
        .unwrap();
    }
    let (out, _, err) = run(&[
        "combine",
        "--in-dir",
        subset.to_str().unwrap(),
        "--out",
        "-",
    ]);
    assert!(!out.status.success());
    assert!(err.contains("not enough shares"));
    assert!(out.stdout.is_empty(), "no secret bytes may be emitted");
}

#[test]
fn cli_tampered_share_detected() {
    let dir = tmp_dir("tamper");
    fs::write(dir.join("s"), b"tamper test data here").unwrap();
    let shares_dir = dir.join("shares");
    run(&[
        "split",
        "-k",
        "2",
        "-n",
        "3",
        "--secret",
        dir.join("s").to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);

    // Flip one byte in the middle of share-002.
    let p = shares_dir.join("share-002.bin");
    let mut bytes = fs::read(&p).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    fs::write(&p, bytes).unwrap();

    let (out, _, err) = run(&[
        "combine",
        "--in-dir",
        shares_dir.to_str().unwrap(),
        "--out",
        "-",
    ]);
    assert!(!out.status.success());
    assert!(err.contains("integrity"), "unexpected message: {err}");
}

#[test]
fn cli_wrong_version_rejected() {
    let dir = tmp_dir("ver");
    fs::write(dir.join("s"), b"version test").unwrap();
    let shares_dir = dir.join("shares");
    run(&[
        "split",
        "-k",
        "2",
        "-n",
        "3",
        "--secret",
        dir.join("s").to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);

    // Rewrite the version byte (offset 4) and fix up the checksum, simulating
    // a validly-formed file from a hypothetical future version.
    let p = shares_dir.join("share-001.bin");
    let mut bytes = fs::read(&p).unwrap();
    bytes[4] = 42;
    let payload_end = bytes.len() - 32;
    let digest = local_sss_test_support::sha256(&bytes[..payload_end]);
    bytes[payload_end..].copy_from_slice(&digest);
    fs::write(&p, bytes).unwrap();

    let (out, _, err) = run(&[
        "combine",
        "--in-dir",
        shares_dir.to_str().unwrap(),
        "--out",
        "-",
    ]);
    assert!(!out.status.success());
    assert!(err.contains("version 42"));
}

#[test]
fn cli_duplicate_index_detected() {
    let dir = tmp_dir("dup");
    fs::write(dir.join("s"), b"duplicate indices").unwrap();
    let shares_dir = dir.join("shares");
    run(&[
        "split",
        "-k",
        "2",
        "-n",
        "3",
        "--secret",
        dir.join("s").to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);

    let dup = dir.join("dup");
    fs::create_dir_all(&dup).unwrap();
    fs::copy(
        shares_dir.join("share-001.bin"),
        dup.join("share-001.bin"),
    )
    .unwrap();
    fs::copy(
        shares_dir.join("share-001.bin"),
        dup.join("share-001-copy.bin"),
    )
    .unwrap();
    fs::copy(
        shares_dir.join("share-002.bin"),
        dup.join("share-002.bin"),
    )
    .unwrap();

    let (out, _, err) = run(&[
        "combine",
        "--in-dir",
        dup.to_str().unwrap(),
        "--out",
        "-",
    ]);
    assert!(!out.status.success());
    assert!(err.contains("duplicate share index 1"));
}

#[test]
fn cli_mixed_different_secrets_detected() {
    let dir = tmp_dir("mix");
    let sa = dir.join("a");
    let sb = dir.join("b");
    fs::write(&sa, b"secret number one!!").unwrap();
    fs::write(&sb, b"secret number two!!").unwrap();
    let da = dir.join("da");
    let db = dir.join("db");
    run(&[
        "split", "-k", "2", "-n", "3",
        "--secret", sa.to_str().unwrap(),
        "--out-dir", da.to_str().unwrap(),
    ]);
    run(&[
        "split", "-k", "2", "-n", "3",
        "--secret", sb.to_str().unwrap(),
        "--out-dir", db.to_str().unwrap(),
    ]);

    let mix = dir.join("mix");
    fs::create_dir_all(&mix).unwrap();
    fs::copy(
        da.join("share-001.bin"),
        mix.join("share-001.bin"),
    )
    .unwrap();
    fs::copy(
        db.join("share-002.bin"),
        mix.join("share-002.bin"),
    )
    .unwrap();

    let (out, _, err) = run(&[
        "combine",
        "--in-dir",
        mix.to_str().unwrap(),
        "--out",
        "-",
    ]);
    assert!(!out.status.success());
    assert!(err.contains("different split operations"), "got: {err}");
}

#[test]
fn cli_oversized_secret_rejected() {
    let dir = tmp_dir("big");
    let big = vec![0u8; 64 * 1024 + 1];
    let p = dir.join("big.bin");
    fs::write(&p, big).unwrap();
    let out_dir = dir.join("shares");
    let (out, _, err) = run(&[
        "split",
        "-k",
        "2",
        "-n",
        "3",
        "--secret",
        p.to_str().unwrap(),
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(err.contains("maximum allowed"));
    assert!(!out_dir.exists(), "no shares should be written");
}

#[test]
fn cli_inspect_reports_metadata_without_share_bytes() {
    let dir = tmp_dir("inspect");
    fs::write(dir.join("s"), b"inspect me").unwrap();
    let shares_dir = dir.join("shares");
    run(&[
        "split",
        "-k",
        "3",
        "-n",
        "5",
        "--secret",
        dir.join("s").to_str().unwrap(),
        "--out-dir",
        shares_dir.to_str().unwrap(),
    ]);
    let (out, stdout, err) =
        run(&["inspect", shares_dir.join("share-003.bin").to_str().unwrap()]);
    assert!(out.status.success(), "{err}");
    assert!(stdout.contains("k=3"));
    assert!(stdout.contains("n=5"));
    assert!(stdout.contains("index=3"));
    assert!(stdout.contains("OK"));
}

// Tiny in-test SHA-256 helper (re-implemented via the library's public API
// is impossible because sha256 is pub; use it directly through the crate).
mod local_sss_test_support {
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        local_sss::sha256::hash(data)
    }
}
