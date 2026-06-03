# json-signer

A CLI tool for signing and verifying JSON configuration files using RSA-2048 / PKCS#1 v1.5 / SHA-256. Signatures are embedded directly in the JSON file as a `_signature` field. Canonical serialization follows RFC 8785 (JSON Canonicalization Scheme) so whitespace and object key order do not affect signatures.

## How It Works

When signing, the tool removes any existing `_signature` field, serializes the remaining top-level JSON object as canonical JSON, signs those bytes, and writes a new `_signature` block back into the file:

```json
{
  "database": "prod-db",
  "max_connections": 100,
  "_signature": {
    "alg": "RS256",
    "kid": "key-v1",
    "signed_at": "2026-06-04T12:00:00Z",
    "sig": "<base64url-encoded signature>"
  }
}
```

Verification re-canonicalizes the payload, again excluding `_signature`, and checks the embedded `sig` value against the provided public key. The process exits with code `0` on a valid signature and code `1` on an invalid signature or other error.

Canonicalization errors are reported instead of panicking. For example, inputs that are valid JSON but cannot be represented under the canonicalization rules, such as integers outside the JSON safe-integer range, fail cleanly.

## Build

Requires the stable Rust toolchain.

```sh
cargo build --release
```

The binary is written to `target/release/json-signer`. The examples below assume it is available on your `PATH` as `json-signer`.

## Usage

### Generate a Key Pair

```sh
json-signer generate-keys
```

Writes `private.pem` (PKCS#8) and `public.pem` (SubjectPublicKeyInfo) to the current directory. On Unix platforms, the private key file is created or rewritten with `0600` permissions.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--private-key <path>` | `private.pem` | Output path for the private key |
| `--public-key <path>` | `public.pem` | Output path for the public key |

### Sign a Config File

```sh
json-signer sign config.json
```

Modifies `config.json` in place by adding or replacing the `_signature` field.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--private-key <path>` | `private.pem` | Path to the RSA private key |
| `--key-id <string>` | `key-v1` | Key identifier stored in the signature block |

### Verify a Config File

```sh
json-signer verify config.json
```

Reads the embedded `_signature` field and verifies it against the public key. Prints the result and exits with code `0` on success or `1` on failure.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--public-key <path>` | `public.pem` | Path to the RSA public key |

## Typical Workflow

```sh
# 1. Generate keys once
json-signer generate-keys --private-key private.pem --public-key public.pem

# 2. Sign a config
json-signer sign config.json --private-key private.pem --key-id deploy-key-v1

# 3. Verify before deployment
json-signer verify config.json --public-key public.pem
```

Keep `private.pem` secret. Distribute `public.pem` to any system that needs to verify configs.

## Security Notes

- On Unix, generated private keys are written with `0600` permissions. On non-Unix platforms, protect private keys with the host operating system's file access controls.
- The verifier uses the public key passed with `--public-key`; it does not perform key lookup from `kid`.
- The `_signature.sig` field is the value that is verified. Treat `alg`, `kid`, and `signed_at` as metadata, not authorization decisions.
- The project uses the RustCrypto `rsa` crate. `.cargo/audit.toml` currently ignores `RUSTSEC-2023-0071` because this is intended as a local CLI tool, not a network-exposed signing service. Revisit that exception before using this code in any service where attackers can trigger signing or observe timing.

## Cryptographic Details

| Property | Value |
|----------|-------|
| Algorithm | RSA-2048 |
| Padding | PKCS#1 v1.5 |
| Hash | SHA-256 |
| Canonicalization | RFC 8785 (JCS) |
| Signature encoding | Base64url without padding |
| Key format (private) | PKCS#8 PEM |
| Key format (public) | SubjectPublicKeyInfo PEM |
| Generated private key permissions (Unix) | `0600` |
