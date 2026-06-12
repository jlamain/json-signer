# json-signer

A CLI tool for signing and verifying JSON configuration files using Ed25519 (default) or RSA-2048 / PKCS#1 v1.5 / SHA-256. Signatures are embedded directly in the JSON file as a `_signature` field. Canonical serialization follows RFC 8785 (JSON Canonicalization Scheme) so whitespace and object key order do not affect signatures.

## How It Works

When signing, the tool replaces any existing `_signature` field with a fresh metadata block (`alg`, `kid`, `signed_at`), serializes the whole document as canonical JSON, signs those bytes, and adds the resulting `sig` value to the block. The signature therefore covers the payload *and* the signature metadata; only the `sig` value itself is excluded:

```json
{
  "database": "prod-db",
  "max_connections": 100,
  "_signature": {
    "alg": "EdDSA",
    "kid": "key-v1",
    "signed_at": "2026-06-04T12:00:00Z",
    "sig": "<base64url-encoded signature>"
  }
}
```

`alg` is `EdDSA` for Ed25519 keys and `RS256` for RSA-2048 keys. `sign` and `verify` detect which algorithm a key uses automatically from its PEM contents, so no algorithm flag is needed for those commands.

Verification re-canonicalizes the document, again excluding only the `sig` value, and checks the embedded signature against the provided public key. Tampering with `alg`, `kid`, or `signed_at` invalidates the signature just like tampering with the payload. The process exits with code `0` on a valid signature and code `1` on an invalid signature or other error.

Input containing duplicate object keys (at any nesting level) is rejected by both `sign` and `verify`: different JSON parsers disagree about which duplicate wins, which would let a verified file mean different things to different consumers.

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

Writes `private.pem` (PKCS#8) and `public.pem` (SubjectPublicKeyInfo) to the current directory. On Unix platforms, the private key file is created with `0600` permissions. The command refuses to overwrite existing key files; move them away or pass different paths to generate a new pair.

By default, an Ed25519 key pair is generated. Pass `--algorithm rsa2048` to generate an RSA-2048 key pair instead.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--private-key <path>` | `private.pem` | Output path for the private key |
| `--public-key <path>` | `public.pem` | Output path for the public key |
| `--algorithm <ed25519\|rsa2048>` | `ed25519` | Key algorithm to generate |

### Sign a Config File

```sh
json-signer sign config.json
```

Modifies `config.json` in place by adding or replacing the `_signature` field.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--private-key <path>` | `private.pem` | Path to the private key (Ed25519 or RSA, PEM) |
| `--key-id <string>` | `key-v1` | Key identifier stored in the signature block |

### Verify a Config File

```sh
json-signer verify config.json
```

Reads the embedded `_signature` field and verifies it against the public key. Prints the result and exits with code `0` on success or `1` on failure.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--public-key <path>` | `public.pem` | Path to the public key (Ed25519 or RSA, PEM) |

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
- `generate-keys` never overwrites existing files, so a key pair cannot be destroyed by re-running the command.
- The verifier uses the public key passed with `--public-key`; it does not perform key lookup from `kid`.
- The `alg`, `kid`, and `signed_at` fields are covered by the signature and cannot be altered after signing. They are still not *checked* by the verifier (no key lookup, no freshness check): in particular, an old config with a valid signature verifies forever, so rotate keys if a signed config must be revoked.
- Ed25519 is the default and recommended algorithm: it is faster, has smaller keys and signatures, and its signatures are deterministic without the PKCS#1 v1.5 padding considerations of RSA. RSA-2048/PKCS#1 v1.5/SHA-256 remains available via `--algorithm rsa2048` for interoperability with systems that require RSA.
- The project uses the RustCrypto `rsa` crate. `.cargo/audit.toml` currently ignores `RUSTSEC-2023-0071` because this is intended as a local CLI tool, not a network-exposed signing service. Revisit that exception before using this code in any service where attackers can trigger signing or observe timing. This does not apply to Ed25519 keys.

## Cryptographic Details

| Property | Ed25519 (default) | RSA-2048 |
|----------|--------------------|----------|
| Algorithm | Ed25519 (EdDSA) | RSA-2048 |
| Padding / hash | N/A (EdDSA, internal SHA-512) | PKCS#1 v1.5 / SHA-256 |
| `alg` value | `EdDSA` | `RS256` |

Shared properties:

| Property | Value |
|----------|-------|
| Canonicalization | RFC 8785 (JCS) |
| Signature encoding | Base64url without padding |
| Key format (private) | PKCS#8 PEM |
| Key format (public) | SubjectPublicKeyInfo PEM |
| Generated private key permissions (Unix) | `0600` |
