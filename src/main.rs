//! JSON Config Signer
//!
//! Signs and verifies JSON config files using RSA-2048 + PKCS#1v15 + SHA-256,
//! with an embedded `_signature` field. Canonical JSON per RFC 8785 (JCS).
//! The signature covers the whole document including the `alg`/`kid`/`signed_at`
//! metadata; only the `sig` value itself is excluded.
//!
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use clap::{Parser, Subcommand};
use pem::{encode as pem_encode, parse as pem_parse, Pem};
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde_json::{Map, Value};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer, Verifier};
use spki::{DecodePublicKey, EncodePublicKey};

const SIGNATURE_FIELD: &str = "_signature";
const PRIVATE_KEY_TAG: &str = "PRIVATE KEY"; // PKCS#8
const PUBLIC_KEY_TAG: &str = "PUBLIC KEY"; // SubjectPublicKeyInfo

/// Clap derived command line parser. Commands can be generate-keys, sign, verify with appropriate arguments.
#[derive(Parser)]
#[command(
    name = "json-config-signer",
    about = "Sign and verify JSON config files (RSA-2048/PKCS#1v15/SHA-256 + RFC 8785)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new RSA-2048 key pair (PKCS#8 PEM)
    GenerateKeys {
        #[arg(
            long,
            default_value = "private.pem",
            help = "Output path for the private key"
        )]
        private_key: PathBuf,

        #[arg(
            long,
            default_value = "public.pem",
            help = "Output path for the public key"
        )]
        public_key: PathBuf,
    },

    /// Sign a JSON config file in-place (adds/replaces the _signature field)
    Sign {
        /// Path to the JSON config file
        config: PathBuf,

        #[arg(
            long,
            default_value = "private.pem",
            help = "Path to the RSA private key (PEM)"
        )]
        private_key: PathBuf,

        #[arg(
            long,
            default_value = "key-v1",
            help = "Key identifier stored in the signature block"
        )]
        key_id: String,
    },

    /// Verify the embedded signature in a JSON config file
    Verify {
        /// Path to the signed JSON config file
        config: PathBuf,

        #[arg(
            long,
            default_value = "public.pem",
            help = "Path to the RSA public key (PEM)"
        )]
        public_key: PathBuf,
    },
}

// Key generation and export functions. Keys are generated as RSA-2048, exported in PKCS#8 (private)
// and SubjectPublicKeyInfo (public) DER format, then PEM-encoded for storage.

fn generate_keys(private_key_path: &Path, public_key_path: &Path) -> Result<()> {
    // Never clobber existing key material; a lost private key is unrecoverable.
    for path in [private_key_path, public_key_path] {
        if path.exists() {
            bail!(
                "Refusing to overwrite existing file {} — move it away or pass a different path",
                path.display()
            );
        }
    }

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).context("Key generation failed")?;
    let public_key = RsaPublicKey::from(&private_key);

    // Private key → PKCS#8 DER → PEM
    let private_der = private_key
        .to_pkcs8_der()
        .context("Failed to export private key")?;
    let private_pem = pem_encode(&Pem::new(PRIVATE_KEY_TAG, private_der.as_bytes()));
    write_private_key(private_key_path, &private_pem)
        .with_context(|| format!("Cannot write {}", private_key_path.display()))?;

    // Public key → SubjectPublicKeyInfo DER → PEM
    let public_der = public_key
        .to_public_key_der()
        .context("Failed to export public key")?;
    let public_pem = pem_encode(&Pem::new(PUBLIC_KEY_TAG, public_der.as_bytes()));
    fs::write(public_key_path, &public_pem)
        .with_context(|| format!("Cannot write {}", public_key_path.display()))?;

    Ok(())
}

fn write_private_key(path: &Path, contents: &str) -> Result<()> {
    write_private_key_bytes(path, contents.as_bytes())?;
    Ok(())
}

#[cfg(unix)]
fn write_private_key_bytes(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_private_key_bytes(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)
}

/// Recursive serde visitor that accepts any JSON value but fails on duplicate object
/// keys at any nesting level. `serde_json` silently keeps the last duplicate, so two
/// parsers can disagree about a signed document's content; RFC 8785 assumes unique
/// keys (I-JSON), so such input must be rejected rather than signed or verified.
struct RejectDuplicateKeys;

impl<'de> serde::de::DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for RejectDuplicateKeys {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key '{key}'"
                )));
            }
            map.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }
}

/// Parse `raw` as a top-level JSON object, rejecting duplicate object keys anywhere
/// in the document.
fn parse_json_object(raw: &str) -> Result<Map<String, Value>> {
    let json: Map<String, Value> = serde_json::from_str(raw).context("Config is not valid JSON")?;

    use serde::de::DeserializeSeed as _;
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    RejectDuplicateKeys
        .deserialize(&mut deserializer)
        .context("Config contains duplicate object keys")?;

    Ok(json)
}

/// Write `contents` to `path` atomically: write a sibling temp file, then rename it
/// over the target, so a crash mid-write cannot leave a truncated file behind.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);

    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Load an RSA private key from a PKCS#8 PEM file.
fn load_private_key(path: &Path) -> Result<RsaPrivateKey> {
    let pem_data =
        fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let pem = pem_parse(&pem_data).context("Failed to parse private key PEM")?;
    RsaPrivateKey::from_pkcs8_der(pem.contents()).context("Failed to load private key")
}

/// Load an RSA public key from a SubjectPublicKeyInfo PEM file.
fn load_public_key(path: &Path) -> Result<RsaPublicKey> {
    let pem_data =
        fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let pem = pem_parse(&pem_data).context("Failed to parse public key PEM")?;
    RsaPublicKey::from_public_key_der(pem.contents()).context("Failed to load public key")
}

/// Sign the canonical form of `json` and insert the resulting `_signature` block,
/// replacing any existing one. The `alg`/`kid`/`signed_at` metadata is inserted
/// before signing, so it is covered by the signature; only `sig` itself is not.
fn embed_signature(
    json: &mut Map<String, Value>,
    private_key: RsaPrivateKey,
    key_id: &str,
    signed_at: &str,
) -> Result<()> {
    json.insert(
        SIGNATURE_FIELD.into(),
        serde_json::json!({
            "alg":       "RS256",
            "kid":       key_id,
            "signed_at": signed_at,
        }),
    );
    let payload = canonicalize(json)?;

    let signing_key = SigningKey::<Sha256>::new(private_key);
    // Sign (PKCS#1v15 is deterministic — no RNG needed at sign time)
    let sig: rsa::pkcs1v15::Signature = signing_key.sign(&payload);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref());

    let Some(Value::Object(sig_block)) = json.get_mut(SIGNATURE_FIELD) else {
        unreachable!("signature block was just inserted as an object");
    };
    sig_block.insert("sig".into(), Value::String(sig_b64));
    Ok(())
}

/// Return the canonical JSON bytes of Map `m`, with only the `sig` value removed
/// from the `_signature` block. Everything else — payload and signature metadata —
/// is part of the signed bytes.
fn canonicalize(m: &Map<String, Value>) -> Result<Vec<u8>> {
    let mut m = m.clone();
    if let Some(Value::Object(sig_block)) = m.get_mut(SIGNATURE_FIELD) {
        sig_block.remove("sig");
    }
    Ok(json_canon::to_string(&Value::Object(m))?.into_bytes())
}

/// Sign the json file at `json_path` using the RSA private key at `private_key_path`, embedding the signature in the `_signature` field.
fn sign_json(json_path: &Path, private_key_path: &Path, key_id: &str) -> Result<()> {
    // Load and parse config
    let raw = fs::read_to_string(json_path)
        .with_context(|| format!("Cannot read {}", json_path.display()))?;
    let mut json = parse_json_object(&raw)?;

    let private_key = load_private_key(private_key_path)?;
    embed_signature(&mut json, private_key, key_id, &Utc::now().to_rfc3339())?;

    let output =
        serde_json::to_string_pretty(&Value::Object(json)).context("Serialization failed")?;
    write_atomic(json_path, &output)
        .with_context(|| format!("Cannot write {}", json_path.display()))?;

    Ok(())
}

/// Verify the embedded `_signature` against the canonical form of `json` (everything
/// except the `sig` value itself, so the `alg`/`kid`/`signed_at` metadata is covered).
///
/// Returns `Ok(false)` for a well-formed signature that does not match, and `Err` for
/// structurally invalid input: missing or non-object `_signature`, missing `sig`,
/// bad base64, or a signature with an impossible length.
fn verify_json(json: &Map<String, Value>, public_key: RsaPublicKey) -> Result<bool> {
    let Some(sig_block) = json.get(SIGNATURE_FIELD).and_then(|v| v.as_object()) else {
        bail!("No '{SIGNATURE_FIELD}' object found in config");
    };

    let sig_b64 = sig_block
        .get("sig")
        .and_then(|v| v.as_str())
        .context("Signature block missing 'sig' field")?;

    let raw_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .context("Failed to base64-decode signature")?;

    let payload = canonicalize(json)?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let signature = rsa::pkcs1v15::Signature::try_from(raw_sig.as_slice())
        .context("Invalid signature bytes")?;

    Ok(verifying_key.verify(&payload, &signature).is_ok())
}

/// Verify the signature embedded in the JSON file at `json_path` using the RSA public key at `public_key_path`.
/// Returns true if valid, false if invalid.
fn load_and_verify_json(json_path: &Path, public_key_path: &Path) -> Result<bool> {
    // Load and parse config
    let raw = fs::read_to_string(json_path)
        .with_context(|| format!("Cannot read {}", json_path.display()))?;
    let json = parse_json_object(&raw)?;

    let public_key = load_public_key(public_key_path)?;

    verify_json(&json, public_key)
}

/// Main entry point: parse CLI args and dispatch to the appropriate command handler.
fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::GenerateKeys {
            private_key,
            public_key,
        } => {
            generate_keys(private_key, public_key)?;
            println!(
                "Keys written to: {}  {}",
                private_key.display(),
                public_key.display()
            );
        }
        Command::Sign {
            config,
            private_key,
            key_id,
        } => {
            sign_json(config, private_key, key_id)?;
            println!("Config signed successfully: {}", config.display());
        }
        Command::Verify { config, public_key } => {
            if load_and_verify_json(config, public_key)? {
                println!("Signature VALID  ✓");
            } else {
                println!("Signature INVALID ✗  — config may have been tampered with!");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use pem::{encode as pem_encode, Pem};
    use rand::rngs::OsRng;
    use rsa::{
        pkcs1v15::{SigningKey, VerifyingKey},
        RsaPrivateKey, RsaPublicKey,
    };
    use serde_json::{json, Map, Value};
    use signature::{Signer, Verifier};
    use spki::EncodePublicKey;
    use std::{fs, path::PathBuf};

    // Use 1024-bit keys in tests for speed (2048 would be too slow for many test runs).
    fn make_test_key_pair() -> (RsaPrivateKey, RsaPublicKey) {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        (priv_key, pub_key)
    }

    fn canonicalize_ok(m: &Map<String, Value>) -> Vec<u8> {
        canonicalize(m).unwrap()
    }

    fn make_map(pairs: &[(&str, Value)]) -> Map<String, Value> {
        let mut m = Map::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.clone());
        }
        m
    }

    // Return a copy of `payload` signed with fixed metadata, via the real signing path.
    fn signed_map(priv_key: RsaPrivateKey, payload: &Map<String, Value>) -> Map<String, Value> {
        let mut m = payload.clone();
        embed_signature(&mut m, priv_key, "test-key", "2024-01-01T00:00:00Z").unwrap();
        m
    }

    // Overwrite one field of the `_signature` block after signing.
    fn tamper_sig_block(m: &mut Map<String, Value>, field: &str, value: Value) {
        m.get_mut(SIGNATURE_FIELD)
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(field.to_string(), value);
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("json_signer_test__{label}"))
    }

    fn write_public_key_file(path: &PathBuf, pub_key: &RsaPublicKey) {
        let der = pub_key.to_public_key_der().unwrap();
        let pem = pem_encode(&Pem::new(PUBLIC_KEY_TAG, der.as_bytes()));
        fs::write(path, pem).unwrap();
    }

    fn write_private_key_file(path: &PathBuf, priv_key: &RsaPrivateKey) {
        let der = priv_key.to_pkcs8_der().unwrap();
        let pem = pem_encode(&Pem::new(PRIVATE_KEY_TAG, der.as_bytes()));
        fs::write(path, pem).unwrap();
    }

    // Build and write a fully signed JSON file with in-process key material, using
    // the same embed_signature path as the sign command.
    fn write_signed_json_file(
        path: &PathBuf,
        priv_key: RsaPrivateKey,
        payload: &Map<String, Value>,
    ) {
        let mut full = payload.clone();
        embed_signature(&mut full, priv_key, "test-k1", "2024-01-01T00:00:00Z").unwrap();
        let out = serde_json::to_string_pretty(&Value::Object(full)).unwrap();
        fs::write(path, out).unwrap();
    }

    #[test]
    fn test_canonicalize_empty_map() {
        let result = canonicalize_ok(&Map::new());
        assert_eq!(result, b"{}");
    }

    #[test]
    fn test_canonicalize_strips_sig_but_keeps_signature_metadata() {
        let m = make_map(&[(SIGNATURE_FIELD, json!({"sig": "abc", "alg": "RS256"}))]);
        assert_eq!(
            String::from_utf8(canonicalize_ok(&m)).unwrap(),
            r#"{"_signature":{"alg":"RS256"}}"#
        );
    }

    #[test]
    fn test_canonicalize_keeps_other_fields() {
        let m = make_map(&[
            ("foo", json!("bar")),
            (SIGNATURE_FIELD, json!({"sig": "abc"})),
        ]);
        assert_eq!(
            String::from_utf8(canonicalize_ok(&m)).unwrap(),
            r#"{"_signature":{},"foo":"bar"}"#
        );
    }

    #[test]
    fn test_canonicalize_without_signature_is_unaffected() {
        let m = make_map(&[("a", json!(1))]);
        assert_eq!(canonicalize_ok(&m), br#"{"a":1}"#);
    }

    #[test]
    fn test_canonicalize_is_deterministic() {
        let m = make_map(&[("b", json!(2)), ("a", json!(1))]);
        assert_eq!(canonicalize_ok(&m), canonicalize_ok(&m));
    }

    #[test]
    fn test_canonicalize_sorts_keys_lexicographically() {
        // RFC 8785 (JCS) mandates lexicographic key order.
        let m = make_map(&[("z", json!(3)), ("a", json!(1)), ("m", json!(2))]);
        assert_eq!(
            String::from_utf8(canonicalize_ok(&m)).unwrap(),
            r#"{"a":1,"m":2,"z":3}"#
        );
    }

    #[test]
    fn test_canonicalize_sorts_nested_object_keys() {
        let m = make_map(&[("cfg", json!({"timeout": 30, "host": "localhost"}))]);
        assert_eq!(
            String::from_utf8(canonicalize_ok(&m)).unwrap(),
            r#"{"cfg":{"host":"localhost","timeout":30}}"#
        );
    }

    #[test]
    fn test_canonicalize_handles_bool_null_number_array() {
        let m = make_map(&[
            ("arr", json!([1, 2, 3])),
            ("b", json!(true)),
            ("n", json!(null)),
            ("num", json!(42)),
        ]);
        let result = String::from_utf8(canonicalize_ok(&m)).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["arr"], json!([1, 2, 3]));
        assert_eq!(parsed["b"], json!(true));
        assert_eq!(parsed["n"], json!(null));
        assert_eq!(parsed["num"], json!(42));
    }

    #[test]
    fn test_canonicalize_preserves_unicode() {
        let m = make_map(&[("greeting", json!("こんにちは"))]);
        let result = canonicalize_ok(&m);
        let parsed: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["greeting"], json!("こんにちは"));
    }

    #[test]
    fn test_canonicalize_escapes_special_string_chars() {
        let m = make_map(&[("s", json!("line1\nline2\ttab\"quote"))]);
        let parsed: Value = serde_json::from_slice(&canonicalize_ok(&m)).unwrap();
        assert_eq!(parsed["s"].as_str().unwrap(), "line1\nline2\ttab\"quote");
    }

    #[test]
    fn test_verify_json_valid_signature_returns_true() {
        let (priv_key, pub_key) = make_test_key_pair();
        let signed = signed_map(
            priv_key,
            &make_map(&[("env", json!("prod")), ("v", json!(2))]),
        );

        assert!(verify_json(&signed, pub_key).unwrap());
    }

    #[test]
    fn test_verify_json_tampered_value_returns_false() {
        let (priv_key, pub_key) = make_test_key_pair();
        let mut signed = signed_map(priv_key, &make_map(&[("env", json!("prod"))]));

        // Change "prod" → "dev" after signing
        signed.insert("env".into(), json!("dev"));

        assert!(!verify_json(&signed, pub_key).unwrap());
    }

    #[test]
    fn test_verify_json_injected_field_returns_false() {
        let (priv_key, pub_key) = make_test_key_pair();
        let mut signed = signed_map(priv_key, &make_map(&[("env", json!("prod"))]));

        signed.insert("injected".into(), json!("evil"));

        assert!(!verify_json(&signed, pub_key).unwrap());
    }

    #[test]
    fn test_verify_json_removed_field_returns_false() {
        let (priv_key, pub_key) = make_test_key_pair();
        let mut signed = signed_map(priv_key, &make_map(&[("a", json!(1)), ("b", json!(2))]));

        signed.remove("b");

        assert!(!verify_json(&signed, pub_key).unwrap());
    }

    #[test]
    fn test_verify_json_tampered_kid_returns_false() {
        let (priv_key, pub_key) = make_test_key_pair();
        let mut signed = signed_map(priv_key, &make_map(&[("env", json!("prod"))]));

        tamper_sig_block(&mut signed, "kid", json!("other-key"));

        assert!(!verify_json(&signed, pub_key).unwrap());
    }

    #[test]
    fn test_verify_json_tampered_signed_at_returns_false() {
        let (priv_key, pub_key) = make_test_key_pair();
        let mut signed = signed_map(priv_key, &make_map(&[("env", json!("prod"))]));

        tamper_sig_block(&mut signed, "signed_at", json!("2030-01-01T00:00:00Z"));

        assert!(!verify_json(&signed, pub_key).unwrap());
    }

    #[test]
    fn test_verify_json_wrong_key_returns_false() {
        let (priv_key, _) = make_test_key_pair();
        let (_, other_pub) = make_test_key_pair();
        let signed = signed_map(priv_key, &make_map(&[("x", json!(1))]));

        assert!(!verify_json(&signed, other_pub).unwrap());
    }

    #[test]
    fn test_verify_json_missing_signature_block_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let payload = make_map(&[("x", json!(1))]);

        let err = verify_json(&payload, pub_key).unwrap_err();
        assert!(err.to_string().contains(SIGNATURE_FIELD));
    }

    #[test]
    fn test_verify_json_missing_sig_field_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let mut payload = make_map(&[("x", json!(1))]);
        payload.insert(SIGNATURE_FIELD.into(), json!({"alg": "RS256"})); // no "sig" key

        let err = verify_json(&payload, pub_key).unwrap_err();
        assert!(err.to_string().contains("sig"));
    }

    #[test]
    fn test_verify_json_invalid_base64_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let mut payload = make_map(&[("x", json!(1))]);
        payload.insert(SIGNATURE_FIELD.into(), json!({"sig": "!!!not-base64!!!"}));

        assert!(verify_json(&payload, pub_key).is_err());
    }

    #[test]
    fn test_verify_json_truncated_signature_does_not_verify() {
        let (_, pub_key) = make_test_key_pair();
        let mut payload = make_map(&[("x", json!(1))]);
        // Valid base64, but far too few bytes to be a valid RSA-1024 signature (128 bytes).
        let bad_sig = URL_SAFE_NO_PAD.encode(b"way_too_short");
        payload.insert(SIGNATURE_FIELD.into(), json!({ "sig": bad_sig }));

        match verify_json(&payload, pub_key) {
            Ok(false) | Err(_) => {} // invalid bytes must not produce Ok(true)
            Ok(true) => panic!("truncated signature must not verify"),
        }
    }

    #[test]
    fn test_verify_json_empty_payload_with_valid_sig_returns_true() {
        let (priv_key, pub_key) = make_test_key_pair();
        let signed = signed_map(priv_key, &Map::new());

        assert!(verify_json(&signed, pub_key).unwrap());
    }

    /// `generate_keys` tests
    #[test]
    fn test_generate_keys_creates_pem_files() {
        let priv_path = temp_path("gen_priv.pem");
        let pub_path = temp_path("gen_pub.pem");
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);

        generate_keys(&priv_path, &pub_path).unwrap();

        assert!(priv_path.exists(), "private key file should exist");
        assert!(pub_path.exists(), "public key file should exist");

        let priv_pem = fs::read_to_string(&priv_path).unwrap();
        let pub_pem = fs::read_to_string(&pub_path).unwrap();
        assert!(priv_pem.contains("PRIVATE KEY"));
        assert!(pub_pem.contains("PUBLIC KEY"));

        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[cfg(unix)]
    #[test]
    fn test_generate_keys_private_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let priv_path = temp_path("gen_priv_owner_only.pem");
        let pub_path = temp_path("gen_pub_owner_only.pem");
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);

        generate_keys(&priv_path, &pub_path).unwrap();

        let mode = fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key file should be owner-only");

        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_generate_keys_produces_parseable_and_matching_pair() {
        let priv_path = temp_path("pair_priv.pem");
        let pub_path = temp_path("pair_pub.pem");
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);

        generate_keys(&priv_path, &pub_path).unwrap();

        let priv_pem_data = fs::read_to_string(&priv_path).unwrap();
        let pub_pem_data = fs::read_to_string(&pub_path).unwrap();

        let priv_parsed = pem::parse(&priv_pem_data).unwrap();
        let pub_parsed = pem::parse(&pub_pem_data).unwrap();

        let priv_key = RsaPrivateKey::from_pkcs8_der(priv_parsed.contents()).unwrap();
        let pub_key = RsaPublicKey::from_public_key_der(pub_parsed.contents()).unwrap();

        let payload = b"round-trip-test";
        let signing_key = SigningKey::<sha2::Sha256>::new(priv_key);
        let sig: rsa::pkcs1v15::Signature = signing_key.sign(payload);
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(pub_key);
        assert!(verifying_key.verify(payload, &sig).is_ok());

        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_generate_keys_invalid_private_key_path_is_error() {
        let bad_priv = PathBuf::from("/nonexistent_dir_abc123/private.pem");
        let pub_path = temp_path("dummy_pub_for_bad_priv.pem");

        let result = generate_keys(&bad_priv, &pub_path);

        assert!(result.is_err());
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_generate_keys_invalid_public_key_path_is_error() {
        let priv_path = temp_path("dummy_priv_for_bad_pub.pem");
        let bad_pub = PathBuf::from("/nonexistent_dir_abc123/public.pem");

        let result = generate_keys(&priv_path, &bad_pub);

        assert!(result.is_err());
        let _ = fs::remove_file(&priv_path);
    }

    #[test]
    fn test_generate_keys_refuses_to_overwrite_existing_files() {
        let priv_path = temp_path("no_overwrite_priv.pem");
        let pub_path = temp_path("no_overwrite_pub.pem");
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);

        generate_keys(&priv_path, &pub_path).unwrap();
        let original_priv = fs::read_to_string(&priv_path).unwrap();

        let err = generate_keys(&priv_path, &pub_path).unwrap_err();
        assert!(err.to_string().contains("Refusing to overwrite"));
        assert_eq!(
            fs::read_to_string(&priv_path).unwrap(),
            original_priv,
            "existing private key must be untouched"
        );

        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }

    /// `sign_json` tests
    #[test]
    fn test_sign_json_round_trips_with_load_and_verify() {
        let (priv_key, pub_key) = make_test_key_pair();
        let json_path = temp_path("sign_rt.json");
        let priv_path = temp_path("sign_rt_priv.pem");
        let pub_path = temp_path("sign_rt_pub.pem");

        fs::write(&json_path, r#"{"env":"prod","version":1}"#).unwrap();
        write_private_key_file(&priv_path, &priv_key);
        write_public_key_file(&pub_path, &pub_key);

        sign_json(&json_path, &priv_path, "rt-key").unwrap();
        assert!(load_and_verify_json(&json_path, &pub_path).unwrap());
        assert!(
            !temp_path("sign_rt.json.tmp").exists(),
            "atomic write must not leave a temp file behind"
        );

        let signed: Value = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(signed[SIGNATURE_FIELD]["kid"], json!("rt-key"));
        assert_eq!(signed["env"], json!("prod"));

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_sign_json_replaces_existing_signature() {
        let (priv_key, pub_key) = make_test_key_pair();
        let json_path = temp_path("sign_resign.json");
        let priv_path = temp_path("sign_resign_priv.pem");
        let pub_path = temp_path("sign_resign_pub.pem");

        // Start with a file signed by a different (throwaway) key.
        let (old_priv, _) = make_test_key_pair();
        let payload = make_map(&[("env", json!("prod"))]);
        write_signed_json_file(&json_path, old_priv, &payload);
        write_private_key_file(&priv_path, &priv_key);
        write_public_key_file(&pub_path, &pub_key);

        sign_json(&json_path, &priv_path, "new-key").unwrap();
        assert!(load_and_verify_json(&json_path, &pub_path).unwrap());

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }

    /// `parse_json_object` tests
    #[test]
    fn test_parse_json_object_accepts_unique_keys() {
        let m = parse_json_object(r#"{"a":1,"b":{"c":2}}"#).unwrap();
        assert_eq!(m["a"], json!(1));
    }

    #[test]
    fn test_parse_json_object_rejects_top_level_duplicate_keys() {
        let err = parse_json_object(r#"{"env":"prod","env":"dev"}"#).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_parse_json_object_rejects_nested_duplicate_keys() {
        let err = parse_json_object(r#"{"cfg":{"host":"a","host":"b"}}"#).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_parse_json_object_rejects_duplicates_inside_arrays() {
        let err = parse_json_object(r#"{"list":[{"k":1,"k":2}]}"#).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_parse_json_object_rejects_non_object_top_level() {
        assert!(parse_json_object("[1,2,3]").is_err());
    }

    #[test]
    fn test_sign_json_rejects_duplicate_keys() {
        let (priv_key, _) = make_test_key_pair();
        let json_path = temp_path("sign_dup.json");
        let priv_path = temp_path("sign_dup_priv.pem");

        fs::write(&json_path, r#"{"env":"prod","env":"dev"}"#).unwrap();
        write_private_key_file(&priv_path, &priv_key);

        let err = sign_json(&json_path, &priv_path, "k").unwrap_err();
        assert!(err.to_string().contains("duplicate"));

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&priv_path);
    }

    #[test]
    fn test_load_and_verify_json_rejects_duplicate_keys() {
        let (priv_key, pub_key) = make_test_key_pair();
        let json_path = temp_path("lv_dup.json");
        let pub_path = temp_path("lv_dup_pub.pem");

        // Sign a clean file, then inject a duplicate key into the raw text.
        let payload = make_map(&[("env", json!("prod"))]);
        write_signed_json_file(&json_path, priv_key, &payload);
        write_public_key_file(&pub_path, &pub_key);

        let raw = fs::read_to_string(&json_path).unwrap();
        let tampered = raw.replacen(
            "\"env\": \"prod\"",
            "\"env\": \"dev\",\n  \"env\": \"prod\"",
            1,
        );
        assert_ne!(raw, tampered, "test setup must inject a duplicate key");
        fs::write(&json_path, tampered).unwrap();

        let err = load_and_verify_json(&json_path, &pub_path).unwrap_err();
        assert!(err.to_string().contains("duplicate"));

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    /// `load_and_verify_json` tests
    #[test]
    fn test_load_and_verify_json_valid_file_returns_true() {
        let (priv_key, pub_key) = make_test_key_pair();
        let json_path = temp_path("lv_valid.json");
        let pub_path = temp_path("lv_valid_pub.pem");

        let payload = make_map(&[("env", json!("prod")), ("version", json!(1))]);
        write_signed_json_file(&json_path, priv_key, &payload);
        write_public_key_file(&pub_path, &pub_key);

        assert!(load_and_verify_json(&json_path, &pub_path).unwrap());

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_tampered_content_returns_false() {
        let (priv_key, pub_key) = make_test_key_pair();
        let json_path = temp_path("lv_tampered.json");
        let pub_path = temp_path("lv_tampered_pub.pem");

        let payload = make_map(&[("env", json!("prod"))]);
        write_signed_json_file(&json_path, priv_key, &payload);
        write_public_key_file(&pub_path, &pub_key);

        // Mutate the file on disk after signing.
        let raw = fs::read_to_string(&json_path).unwrap();
        fs::write(&json_path, raw.replace("\"prod\"", "\"dev\"")).unwrap();

        assert!(!load_and_verify_json(&json_path, &pub_path).unwrap());

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_missing_signature_field_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let json_path = temp_path("lv_nosig.json");
        let pub_path = temp_path("lv_nosig_pub.pem");

        fs::write(&json_path, r#"{"env":"prod"}"#).unwrap();
        write_public_key_file(&pub_path, &pub_key);

        let err = load_and_verify_json(&json_path, &pub_path).unwrap_err();
        assert!(err.to_string().contains(SIGNATURE_FIELD));

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_signature_field_not_object_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let json_path = temp_path("lv_sig_scalar.json");
        let pub_path = temp_path("lv_sig_scalar_pub.pem");

        // _signature is a plain string, not an object.
        fs::write(
            &json_path,
            format!(r#"{{"env":"prod","{SIGNATURE_FIELD}":"not-an-object"}}"#),
        )
        .unwrap();
        write_public_key_file(&pub_path, &pub_key);

        let err = load_and_verify_json(&json_path, &pub_path).unwrap_err();
        assert!(err.to_string().contains(SIGNATURE_FIELD));

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_nonexistent_json_file_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let json_path = PathBuf::from("/nonexistent_dir_abc123/config.json");
        let pub_path = temp_path("lv_ne_pub.pem");
        write_public_key_file(&pub_path, &pub_key);

        assert!(load_and_verify_json(&json_path, &pub_path).is_err());

        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_nonexistent_key_file_is_error() {
        let (priv_key, _) = make_test_key_pair();
        let json_path = temp_path("lv_nokey.json");
        let pub_path = PathBuf::from("/nonexistent_dir_abc123/public.pem");

        let payload = make_map(&[("x", json!(1))]);
        write_signed_json_file(&json_path, priv_key, &payload);

        assert!(load_and_verify_json(&json_path, &pub_path).is_err());

        let _ = fs::remove_file(&json_path);
    }

    #[test]
    fn test_load_and_verify_json_invalid_json_content_is_error() {
        let (_, pub_key) = make_test_key_pair();
        let json_path = temp_path("lv_badjson.json");
        let pub_path = temp_path("lv_badjson_pub.pem");

        fs::write(&json_path, "not valid json {{{{").unwrap();
        write_public_key_file(&pub_path, &pub_key);

        assert!(load_and_verify_json(&json_path, &pub_path).is_err());

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_corrupt_pem_is_error() {
        let (priv_key, _) = make_test_key_pair();
        let json_path = temp_path("lv_badpem.json");
        let pub_path = temp_path("lv_badpem_pub.pem");

        let payload = make_map(&[("x", json!(1))]);
        write_signed_json_file(&json_path, priv_key, &payload);
        fs::write(
            &pub_path,
            "-----BEGIN PUBLIC KEY-----\n!!!not-valid-base64!!!\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();

        assert!(load_and_verify_json(&json_path, &pub_path).is_err());

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }

    #[test]
    fn test_load_and_verify_json_wrong_public_key_returns_false() {
        let (priv_key, _) = make_test_key_pair();
        let (_, other_pub) = make_test_key_pair();
        let json_path = temp_path("lv_wrongkey.json");
        let pub_path = temp_path("lv_wrongkey_pub.pem");

        let payload = make_map(&[("env", json!("prod"))]);
        write_signed_json_file(&json_path, priv_key, &payload);
        write_public_key_file(&pub_path, &other_pub);

        assert!(!load_and_verify_json(&json_path, &pub_path).unwrap());

        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&pub_path);
    }
}
