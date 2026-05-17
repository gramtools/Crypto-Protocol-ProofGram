import forge from 'node-forge';
import * as bip39 from 'bip39';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { x25519 } from '@noble/curves/ed25519';

// Browser-compatible encoding helpers (no Node.js Buffer)
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

const DB_NAME = 'MessageGramKeys';
const STORE_NAME = 'keys';
const KEY_ID = 'user-keypair';

interface StoredKeyPair {
  publicKeyPem: string;   // base64 X25519 public (44 chars) OR legacy RSA PEM
  privateKeyPem: string;  // hex X25519 private (64 chars) OR legacy RSA PEM
  createdAt: string;
  keyType?: 'ec' | 'rsa';
  mnemonic?: string;      // 12-word recovery phrase (EC only)
}

// ==================== IndexedDB ====================

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
    };
  });
}

// ==================== EC Key Generation (X25519) ====================

/**
 * Generate X25519 key pair from 12-word BIP39 mnemonic.
 * 
 * Flow: mnemonic → 128-bit seed → HKDF → 32-byte X25519 private key → public key
 * Private key stays exclusively on the client.
 */
export async function generateKeyPair(): Promise<{
  publicKeyPem: string;
  privateKeyPem: string;
  mnemonic: string;
}> {
  // Generate 128 bits of entropy → 12 BIP39 words
  const mnemonic = bip39.generateMnemonic(128);
  return deriveKeysFromMnemonic(mnemonic);
}

/**
 * Derive X25519 keys from an existing mnemonic (for restore).
 */
export async function deriveKeysFromMnemonic(mnemonic: string): Promise<{
  publicKeyPem: string;
  privateKeyPem: string;
  mnemonic: string;
}> {
  // Mnemonic → seed bytes (64 bytes via PBKDF2)
  const seedBuffer = await bip39.mnemonicToSeed(mnemonic);
  const seed = new Uint8Array(seedBuffer);

  // HKDF: derive 32-byte X25519 private key
  const privateKeyBytes = hkdf(sha256, seed, 'messagesgram-x25519', 'key-derivation', 32);

  // X25519 public key from private key
  const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);

  // Store as hex (private) and base64 (public — sent to server)
  const privateKeyHex = bytesToHex(new Uint8Array(privateKeyBytes));
  const publicKeyB64 = bytesToBase64(new Uint8Array(publicKeyBytes));

  return {
    publicKeyPem: publicKeyB64,     // 44 chars base64 (32 bytes)
    privateKeyPem: privateKeyHex,   // 64 chars hex (32 bytes)
    mnemonic,
  };
}

// ==================== Save / Load / Delete ====================

export async function saveKeyPair(publicKeyPem: string, privateKeyPem: string, mnemonic?: string): Promise<void> {
  const db = await openDB();
  const keyType = publicKeyPem.includes('-----BEGIN') ? 'rsa' : 'ec';
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.put({
      id: KEY_ID,
      publicKeyPem,
      privateKeyPem,
      createdAt: new Date().toISOString(),
      keyType,
      mnemonic,
    });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadKeyPair(): Promise<StoredKeyPair | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(KEY_ID);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

export async function deleteKeyPair(): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.delete(KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ==================== Recovery (mnemonic-based) ====================

/**
 * Generate 12-word mnemonic recovery phrase.
 * For EC keys: returns the stored mnemonic.
 * For RSA keys (legacy): returns base64 chunked recovery key.
 */
export function generateRecoveryKey(privateKeyPem: string): string {
  // EC keys are stored as hex (64 chars), RSA as PEM
  if (!privateKeyPem.includes('-----BEGIN')) {
    // This shouldn't be called for EC — mnemonic is returned from generateKeyPair
    return privateKeyPem; // hex private key as fallback
  }
  const raw = forge.util.encode64(privateKeyPem);
  return raw.match(/.{1,5}/g)!.join('-');
}

export function restoreFromRecoveryKey(recoveryKey: string): string {
  const raw = recoveryKey.replace(/-/g, '');
  return forge.util.decode64(raw);
}

// ==================== Signing & Fingerprint ====================

/**
 * Sign data with private key (supports RSA and EC keys).
 * RSA: uses RSA-SHA256 signature
 * EC: uses Ed25519 signature (proper cryptographic signature, not HMAC)
 */
export async function signData(data: string, privateKeyPem: string): Promise<string> {
  if (privateKeyPem.includes('-----BEGIN')) {
    // RSA signing (legacy)
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const md = forge.md.sha256.create();
    md.update(data, 'utf8');
    const signature = privateKey.sign(md);
    return forge.util.encode64(signature);
  }
  
  // EC: Ed25519 signature (proper cryptographic signature)
  const { ed25519 } = await import('@noble/curves/ed25519');
  const privateKeyBytes = hexToBytes(privateKeyPem);
  const dataBytes = new TextEncoder().encode(data);
  const signature = ed25519.sign(dataBytes, privateKeyBytes);
  return bytesToBase64(signature);
}

/**
 * Get Ed25519 signing public key from private key (EC only).
 * Used for key rotation: server converts this to X25519 to verify ownership.
 */
export async function getSigningPublicKey(privateKeyPem: string): Promise<string | null> {
  if (privateKeyPem.includes('-----BEGIN')) return null; // RSA doesn't need this
  const { ed25519 } = await import('@noble/curves/ed25519');
  const privateKeyBytes = hexToBytes(privateKeyPem);
  const pubKey = ed25519.getPublicKey(privateKeyBytes);
  return bytesToBase64(pubKey);
}

export function getKeyFingerprint(publicKey: string): string {
  if (publicKey.includes('-----BEGIN')) {
    return forge.md.sha256.create().update(publicKey).digest().toHex().slice(0, 16);
  }
  const bytes = new TextEncoder().encode(publicKey);
  return bytesToHex(sha256(bytes)).slice(0, 16);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Fast base64 → Uint8Array (handles large files without atob stack overflow)
function base64ToUint8Array(b64: string): Uint8Array {
  const binStr = atob(b64);
  const len = binStr.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}

// AES-256-GCM decrypt using Web Crypto (handles large binary natively)
async function aesGcmDecrypt(aesKeyBytes: Uint8Array, ivBytes: Uint8Array, combined: Uint8Array): Promise<Uint8Array> {
  // Web Crypto expects tag appended to ciphertext (which is how our combined format works)
  const key = await crypto.subtle.importKey('raw', aesKeyBytes.buffer as ArrayBuffer, 'AES-GCM', false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes.buffer as ArrayBuffer }, key, combined.buffer as ArrayBuffer);
  return new Uint8Array(decrypted);
}

// Sync AES-GCM decrypt via forge (for small data like text messages)
function aesGcmDecryptSync(aesKeyRaw: string, ivRaw: string, ciphertext: string, authTag: string): string {
  const decipher = forge.cipher.createDecipher('AES-GCM', aesKeyRaw);
  decipher.start({ iv: ivRaw, tag: forge.util.createBuffer(authTag) });
  decipher.update(forge.util.createBuffer(ciphertext));
  if (!decipher.finish()) throw new Error('Decryption failed');
  return decipher.output.getBytes();
}

// ==================== ECIES Decrypt (X25519 + HKDF + AES-256-GCM) ====================

function eciesDecryptRaw(
  encryptedContent: string,
  ephemeralPubKeyB64: string,
  ivB64: string,
  privateKeyHex: string
): Uint8Array {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const ephemeralPubKey = base64ToUint8Array(ephemeralPubKeyB64);
  const ivBytes = base64ToUint8Array(ivB64);

  // ECDH shared secret
  const sharedSecret = x25519.getSharedSecret(privateKeyBytes, ephemeralPubKey);

  // HKDF → AES key (must match backend: salt=ephemeralPubKey, info='messagesgram-v1')
  const aesKey = hkdf(sha256, sharedSecret, ephemeralPubKey, 'messagesgram-v1', 32);

  // Decode combined ciphertext + authTag (last 16 bytes)
  const combined = base64ToUint8Array(encryptedContent);
  const ciphertext = combined.slice(0, combined.length - 16);
  const authTag = combined.slice(combined.length - 16);

  // AES-256-GCM decrypt using forge (sync, for small messages)
  const aesKeyStr = String.fromCharCode(...aesKey);
  const ivStr = String.fromCharCode(...ivBytes);
  const decipher = forge.cipher.createDecipher('AES-GCM', aesKeyStr);
  decipher.start({
    iv: ivStr,
    tag: forge.util.createBuffer(String.fromCharCode(...authTag)),
  });
  decipher.update(forge.util.createBuffer(String.fromCharCode(...ciphertext)));
  const pass = decipher.finish();

  if (!pass) {
    throw new Error('ECIES decryption failed');
  }

  const output = decipher.output.getBytes();
  const bytes = new Uint8Array(output.length);
  for (let i = 0; i < output.length; i++) {
    bytes[i] = output.charCodeAt(i);
  }
  return bytes;
}

// Async ECIES decrypt for large binary (uses Web Crypto)
async function eciesDecryptRawAsync(
  encryptedContent: string,
  ephemeralPubKeyB64: string,
  ivB64: string,
  privateKeyHex: string
): Promise<Uint8Array> {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const ephemeralPubKey = base64ToUint8Array(ephemeralPubKeyB64);
  const ivBytes = base64ToUint8Array(ivB64);
  const sharedSecret = x25519.getSharedSecret(privateKeyBytes, ephemeralPubKey);
  const aesKey = hkdf(sha256, sharedSecret, ephemeralPubKey, 'messagesgram-v1', 32);
  const combined = base64ToUint8Array(encryptedContent);
  return aesGcmDecrypt(new Uint8Array(aesKey), ivBytes, combined);
}

function isECPrivateKey(key: string): boolean {
  return !key.includes('-----BEGIN');
}

/**
 * Decrypt message payload. Supports EC (ECIES) and legacy RSA.
 * For EC: encrypted_aes_key contains ephemeral public key (32 bytes base64).
 * For RSA: encrypted_aes_key contains RSA-encrypted AES key.
 */
export function decryptMessage(
  encryptedContent: string,
  encryptedAesKey: string,
  iv: string,
  privateKeyPem: string
): string {
  if (isECPrivateKey(privateKeyPem)) {
    const raw = eciesDecryptRaw(encryptedContent, encryptedAesKey, iv, privateKeyPem);
    return new TextDecoder().decode(raw);
  }
  return legacyRsaDecryptMessage(encryptedContent, encryptedAesKey, iv, privateKeyPem);
}

/**
 * Decrypt binary data. Supports EC (ECIES) and legacy RSA.
 */
export function decryptBinary(
  encryptedContent: string,
  encryptedAesKey: string,
  iv: string,
  privateKeyPem: string
): Uint8Array {
  if (isECPrivateKey(privateKeyPem)) {
    return eciesDecryptRaw(encryptedContent, encryptedAesKey, iv, privateKeyPem);
  }
  return legacyRsaDecryptBinary(encryptedContent, encryptedAesKey, iv, privateKeyPem);
}

/**
 * Async decrypt binary data — uses Web Crypto for large files (video etc).
 */
export async function decryptBinaryAsync(
  encryptedContent: string,
  encryptedAesKey: string,
  iv: string,
  privateKeyPem: string
): Promise<Uint8Array> {
  if (isECPrivateKey(privateKeyPem)) {
    return eciesDecryptRawAsync(encryptedContent, encryptedAesKey, iv, privateKeyPem);
  }
  // RSA: decrypt AES key with forge (small), then use Web Crypto for bulk
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const aesKeyStr = privateKey.decrypt(
    forge.util.decode64(encryptedAesKey),
    'RSA-OAEP',
    { md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() } }
  );
  const aesKeyBytes = new Uint8Array(aesKeyStr.length);
  for (let i = 0; i < aesKeyStr.length; i++) aesKeyBytes[i] = aesKeyStr.charCodeAt(i);
  const ivBytes = base64ToUint8Array(iv);
  const combined = base64ToUint8Array(encryptedContent);
  return aesGcmDecrypt(aesKeyBytes, ivBytes, combined);
}

// ==================== Legacy RSA Decrypt ====================

function legacyRsaDecryptMessage(
  encryptedContent: string,
  encryptedAesKey: string,
  iv: string,
  privateKeyPem: string
): string {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const aesKeyBytes = privateKey.decrypt(
    forge.util.decode64(encryptedAesKey),
    'RSA-OAEP',
    {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() },
    }
  );

  const [encData, authTagB64] = encryptedContent.split('.');
  const ivBytes = forge.util.decode64(iv);

  const decipher = forge.cipher.createDecipher('AES-GCM', aesKeyBytes);
  decipher.start({
    iv: ivBytes,
    tag: forge.util.createBuffer(forge.util.decode64(authTagB64)),
  });
  decipher.update(forge.util.createBuffer(forge.util.decode64(encData)));
  const pass = decipher.finish();

  if (!pass) {
    throw new Error('Decryption failed — invalid key or corrupted data');
  }

  return decipher.output.toString();
}

function legacyRsaDecryptBinary(
  encryptedContent: string,
  encryptedAesKey: string,
  iv: string,
  privateKeyPem: string
): Uint8Array {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const aesKeyBytes = privateKey.decrypt(
    forge.util.decode64(encryptedAesKey),
    'RSA-OAEP',
    {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() },
    }
  );

  const combined = forge.util.decode64(encryptedContent);
  const encrypted = combined.slice(0, combined.length - 16);
  const authTag = combined.slice(combined.length - 16);
  const ivBytes = forge.util.decode64(iv);

  const decipher = forge.cipher.createDecipher('AES-GCM', aesKeyBytes);
  decipher.start({
    iv: ivBytes,
    tag: forge.util.createBuffer(authTag),
  });
  decipher.update(forge.util.createBuffer(encrypted));
  const pass = decipher.finish();

  if (!pass) {
    throw new Error('Decryption failed');
  }

  const output = decipher.output.getBytes();
  const bytes = new Uint8Array(output.length);
  for (let i = 0; i < output.length; i++) {
    bytes[i] = output.charCodeAt(i);
  }
  return bytes;
}

/**
 * Export private key as an encrypted backup file.
 * v2: AES-256-GCM + PBKDF2 600k iterations (was CBC + 100k).
 * GCM provides authenticated encryption — prevents padding oracle attacks.
 */
export function exportKeyBackup(privateKeyPem: string, passphrase: string): string {
  const salt = forge.random.getBytesSync(32);
  const key = forge.pkcs5.pbkdf2(passphrase, salt, 600000, 32);
  const iv = forge.random.getBytesSync(12); // 96-bit IV for GCM

  const cipher = forge.cipher.createCipher('AES-GCM', key);
  cipher.start({ iv, tagLength: 128 });
  cipher.update(forge.util.createBuffer(privateKeyPem));
  cipher.finish();

  const backup = {
    version: 2,
    salt: forge.util.encode64(salt),
    iv: forge.util.encode64(iv),
    tag: forge.util.encode64(cipher.mode.tag.getBytes()),
    data: forge.util.encode64(cipher.output.getBytes()),
  };

  return JSON.stringify(backup);
}

/**
 * Import private key from encrypted backup.
 * Supports v1 (AES-CBC, legacy) and v2 (AES-GCM, current).
 */
export function importKeyBackup(backupJson: string, passphrase: string): string {
  const backup = JSON.parse(backupJson);

  if (backup.version === 1) {
    return importKeyBackupV1(backup, passphrase);
  }
  if (backup.version === 2) {
    return importKeyBackupV2(backup, passphrase);
  }
  throw new Error('Unsupported backup version');
}

function importKeyBackupV1(backup: any, passphrase: string): string {
  const salt = forge.util.decode64(backup.salt);
  const key = forge.pkcs5.pbkdf2(passphrase, salt, 100000, 32);
  const iv = forge.util.decode64(backup.iv);

  const decipher = forge.cipher.createDecipher('AES-CBC', key);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(forge.util.decode64(backup.data)));
  const pass = decipher.finish();

  if (!pass) {
    throw new Error('Invalid passphrase or corrupted backup');
  }

  return decipher.output.toString();
}

function importKeyBackupV2(backup: any, passphrase: string): string {
  const salt = forge.util.decode64(backup.salt);
  const key = forge.pkcs5.pbkdf2(passphrase, salt, 600000, 32);
  const iv = forge.util.decode64(backup.iv);
  const tag = forge.util.decode64(backup.tag);

  const decipher = forge.cipher.createDecipher('AES-GCM', key);
  decipher.start({
    iv,
    tag: forge.util.createBuffer(tag),
  });
  decipher.update(forge.util.createBuffer(forge.util.decode64(backup.data)));
  const pass = decipher.finish();

  if (!pass) {
    throw new Error('Invalid passphrase or corrupted backup');
  }

  return decipher.output.toString();
}

