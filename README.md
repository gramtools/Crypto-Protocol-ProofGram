# ProofGram — Encryption Protocol

This folder contains the complete open-source cryptographic core of **ProofGram** — an end-to-end encrypted Telegram Business message archive.

> **The server never sees message content.** All encryption and decryption happens on the client device. The private key never leaves the user's device.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Telegram Business Bot                  │
│   Receives message → encrypts with user's public key    │
│   → stores ciphertext in DB / S3                        │
└──────────────────────────┬──────────────────────────────┘
                           │ encrypted blob (server-opaque)
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Mini App (Browser)                    │
│   Loads private key from IndexedDB                      │
│   → decrypts locally → renders message                  │
└─────────────────────────────────────────────────────────┘
```

---

## Key Generation (`client/keys.ts`)

```
BIP39 mnemonic (12 words, 128-bit entropy)
    │
    ▼ bip39.mnemonicToSeed() — PBKDF2, 2048 iterations
64-byte seed
    │
    ▼ HKDF-SHA256(seed, salt="messagesgram-x25519", info="key-derivation", 32 bytes)
32-byte X25519 private key  ← stored in IndexedDB (never sent to server)
    │
    ▼ x25519.getPublicKey()
32-byte X25519 public key   ← base64-encoded, sent to server on registration
```

- Key type: **X25519** (Curve25519 Diffie-Hellman)
- Entropy source: `bip39.generateMnemonic(128)` — 12 words
- Private key storage: **IndexedDB** (browser only), never transmitted
- Public key format: 32 bytes, base64url (44 chars)

---

## Message Encryption — ECIES (`server/encrypt.ts`)

Used by the bot server when a new Business message arrives.

```
Input: plaintext message, user's X25519 public key

1. Generate ephemeral X25519 key pair (random, per-message)

2. ECDH:
   shared_secret = DH(ephemeral_private, user_public)   ← 32 bytes

3. HKDF-SHA256:
   aes_key = HKDF(shared_secret, salt=ephemeral_public, info="messagesgram-v1", 32 bytes)

4. AES-256-GCM encrypt:
   iv = random 12 bytes
   ciphertext || auth_tag = AES-GCM(aes_key, iv, plaintext)

5. Store in database:
   encrypted_content  = base64(ciphertext || auth_tag)   ← 16-byte tag appended
   encrypted_aes_key  = base64(ephemeral_public_key)     ← field name reused for compat
   iv                 = base64(iv)
```

**The server discards the ephemeral private key immediately after encryption.**  
Only the ephemeral *public* key is stored — useless without the user's private key.

---

## Message Decryption — ECIES (`client/keys.ts`)

Performed entirely in the browser (Mini App).

```
Input: encrypted_content, encrypted_aes_key (= ephemeral pub key), iv, user private key (hex)

1. ECDH:
   shared_secret = x25519.getSharedSecret(user_private, ephemeral_public)

2. HKDF-SHA256:
   aes_key = HKDF(shared_secret, salt=ephemeral_public, info="messagesgram-v1", 32 bytes)

3. AES-256-GCM decrypt:
   combined = base64_decode(encrypted_content)
   ciphertext = combined[0 .. len-16]
   auth_tag   = combined[len-16 .. len]
   plaintext  = AES-GCM-Decrypt(aes_key, iv, ciphertext, auth_tag)
```

If auth_tag verification fails → decryption throws, content is never shown.

---

## Key Backup (`client/keys.ts`)

The private key can be exported as an encrypted file for recovery.

```
Input: private key (hex), user passphrase

v2 (current):
  salt = random 32 bytes
  key  = PBKDF2-SHA1(passphrase, salt, 600_000 iterations, 32 bytes)
  iv   = random 12 bytes
  encrypted_key || tag = AES-256-GCM(key, iv, private_key_hex)

Output JSON: { version: 2, salt, iv, tag, data }
```

- 600,000 PBKDF2 iterations — resistant to brute-force
- AES-GCM provides authenticated encryption — detects tampered backups
- v1 backups (AES-CBC, 100k iterations) are read-only supported for migration

---

## API Authentication (`auth/initdata-validation.ts`)

The Mini App authenticates to the backend using Telegram's `initData` mechanism.

```
Telegram signs initData with: HMAC-SHA256(data_check_string, secret_key)
  where secret_key = HMAC-SHA256("WebAppData", bot_token)

Server validates:
  1. Recompute HMAC — constant-time comparison (crypto.timingSafeEqual)
  2. Check auth_date TTL: max 1 hour
  3. Issue a server-side session token (32 random bytes, 1h TTL)
     → returned in X-Session-Token response header
  4. Subsequent requests use X-Session-Token (avoids repeated HMAC)
```

---

## Key Rotation / Signing

When a user rotates their key pair, they must prove ownership of the old key.

```
EC key rotation:
  1. Client signs new_public_key with old Ed25519 key
     (X25519 private key bytes are reused as Ed25519 private key)
  2. Backend verifies Ed25519 signature
  3. Only if valid → public key updated in DB

RSA key rotation (legacy):
  Uses RSA-SHA256 signature
```

---

## Security Properties

| Property | Value |
|---|---|
| Encryption scheme | ECIES (X25519 + HKDF-SHA256 + AES-256-GCM) |
| Key agreement | X25519 (Curve25519) |
| KDF | HKDF-SHA256 |
| Symmetric cipher | AES-256-GCM (authenticated) |
| Key derivation from mnemonic | BIP39 PBKDF2 → HKDF-SHA256 |
| Backup encryption | AES-256-GCM + PBKDF2 (600k iter) |
| Auth | HMAC-SHA256 (Telegram initData) + session token |
| Key storage | IndexedDB (browser-only, never transmitted) |
| Forward secrecy | Per-message ephemeral key pairs |
| Server knowledge | Zero — sees only ciphertext + ephemeral public keys |

---

## Files

| File | Description |
|---|---|
| `server/encrypt.ts` | Server-side ECIES encryption (Node.js) |
| `client/keys.ts` | Client-side key generation, storage, and decryption (Browser) |
| `auth/initdata-validation.ts` | Telegram Mini App authentication middleware |

---

## Dependencies

**Server:** `node:crypto` (built-in), `node-forge`  
**Client:** `bip39`, `@noble/hashes` (hkdf, sha256), `@noble/curves` (x25519, ed25519), `node-forge`

All cryptographic primitives are well-audited open-source libraries.
