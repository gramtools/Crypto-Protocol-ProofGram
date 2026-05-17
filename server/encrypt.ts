import crypto from 'crypto';
import forge from 'node-forge';
import { EncryptedPayload } from '../types';

/**
 * ECIES encryption using X25519 + HKDF + AES-256-GCM.
 * 
 * Protocol:
 * 1. Generate ephemeral X25519 key pair
 * 2. ECDH(ephemeral_private, user_public) → shared_secret
 * 3. HKDF(shared_secret, salt=ephemeral_public) → aes_key (32 bytes)
 * 4. AES-256-GCM encrypt data
 * 5. Store: ephemeral_public_key (in encrypted_aes_key field) + encrypted_content + iv
 * 
 * The server NEVER has access to the private key.
 * 
 * Public key format: 32-byte X25519 public key, base64-encoded.
 * Falls back to legacy RSA for users with RSA PEM keys (migration period).
 */

function isECKey(publicKey: string): boolean {
  // EC keys are 44 chars base64 (32 bytes), RSA keys start with -----BEGIN
  return !publicKey.includes('-----BEGIN');
}

function eciesEncrypt(data: Buffer, userPublicKeyB64: string): EncryptedPayload {
  const userPublicKey = Buffer.from(userPublicKeyB64, 'base64');

  // 1. Generate ephemeral X25519 key pair
  const ephemeral = crypto.generateKeyPairSync('x25519');
  const ephemeralPublicRaw = ephemeral.publicKey.export({ type: 'spki', format: 'der' });
  // X25519 SPKI DER is 44 bytes, last 32 are the raw key
  const ephemeralPublicKey = ephemeralPublicRaw.subarray(ephemeralPublicRaw.length - 32);

  // 2. ECDH shared secret
  const userPubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([
      // X25519 SPKI prefix (12 bytes)
      Buffer.from('302a300506032b656e032100', 'hex'),
      userPublicKey,
    ]),
    format: 'der',
    type: 'spki',
  });
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: userPubKeyObj,
  });

  // 3. HKDF → AES key
  const aesKey = crypto.hkdfSync('sha256', sharedSecret, ephemeralPublicKey, 'messagesgram-v1', 32);

  // 4. AES-256-GCM encrypt
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(aesKey), iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encrypted_content: Buffer.concat([encrypted, authTag]).toString('base64'),
    // Store ephemeral public key (32 bytes) instead of encrypted AES key
    encrypted_aes_key: ephemeralPublicKey.toString('base64'),
    iv: iv.toString('base64'),
  };
}

export function encryptForUser(data: string, publicKey: string): EncryptedPayload {
  if (isECKey(publicKey)) {
    return eciesEncrypt(Buffer.from(data, 'utf8'), publicKey);
  }
  return legacyRsaEncrypt(data, publicKey);
}

export function encryptBinaryForUser(data: Buffer, publicKey: string): EncryptedPayload {
  if (isECKey(publicKey)) {
    return eciesEncrypt(data, publicKey);
  }
  return legacyRsaBinaryEncrypt(data, publicKey);
}

// ==================== LEGACY RSA (backward compat) ====================

function legacyRsaEncrypt(data: string, publicKeyPem: string): EncryptedPayload {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  const encryptedContent = encrypted + '.' + authTag.toString('base64');

  const rsaPubKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const encryptedAesKey = rsaPubKey.encrypt(
    aesKey.toString('binary'),
    'RSA-OAEP',
    { md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() } }
  );

  return {
    encrypted_content: encryptedContent,
    encrypted_aes_key: forge.util.encode64(encryptedAesKey),
    iv: iv.toString('base64'),
  };
}

function legacyRsaBinaryEncrypt(data: Buffer, publicKeyPem: string): EncryptedPayload {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([encrypted, authTag]);

  const rsaPubKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const encryptedAesKey = rsaPubKey.encrypt(
    aesKey.toString('binary'),
    'RSA-OAEP',
    { md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() } }
  );

  return {
    encrypted_content: combined.toString('base64'),
    encrypted_aes_key: forge.util.encode64(encryptedAesKey),
    iv: iv.toString('base64'),
  };
}
