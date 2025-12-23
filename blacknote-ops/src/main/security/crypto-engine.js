const crypto = require('crypto');
const { getDeviceFingerprint } = require('./device-id');

// Try to load argon2, but provide a mock if it fails (for environment compatibility)
let argon2;
try {
  argon2 = require('argon2');
} catch (e) {
  console.warn("WARNING: 'argon2' native module not found. Using fallback PBKDF2 for demonstration purposes ONLY. PROD MUST USE ARGON2.");
  argon2 = null;
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 12-16 bytes is standard for GCM, 16 is fine. 12 is recommended for performance. let's use 16 (default for many) or 12. GCM standard is often 12 (96 bits). Node's crypto often handles 16. Let's stick to 12 for GCM best practice, or 16 if safe. I'll use 16.

/**
 * The VaultCryptoEngine handles the lifecycle of the Master Key.
 * It enforces the rule: Master Key is never stored, only derived.
 */
class VaultCryptoEngine {
  constructor() {
    this.masterKey = null; // Buffer
    this.deviceFingerprint = getDeviceFingerprint();
  }

  /**
   * Derives the Master Key from Password + DeviceID + Salt
   * @param {string} password
   * @param {Buffer} salt
   */
  async deriveKey(password, salt) {
    // 1. Combine Password with Device Fingerprint (Device Binding)
    const entropy = `${password}::${this.deviceFingerprint}`;

    if (argon2) {
      // PROD: Use Argon2id
      // We use argon2.hash to get a raw buffer if possible, or we hash the hash.
      // Actually argon2 returns a string format usually. We need a raw key.
      // A common trick is to use the raw hash output.
      // But argon2 lib allows 'raw: true'.
      const key = await argon2.hash(entropy, {
        type: argon2.argon2id,
        raw: true,
        salt: salt,
        hashLength: 32, // AES-256 needs 32 bytes
        timeCost: 3,
        memoryCost: 65536, // 64 MB
        parallelism: 1
      });
      return key;
    } else {
      // FALLBACK (Sandbox/Dev without native modules)
      return new Promise((resolve, reject) => {
        crypto.pbkdf2(entropy, salt, 100000, 32, 'sha512', (err, key) => {
          if (err) reject(err);
          else resolve(key);
        });
      });
    }
  }

  /**
   * Generates a new random salt for a new vault.
   */
  generateSalt() {
    return crypto.randomBytes(16);
  }

  /**
   * Unlocks the vault by attempting to derive the key.
   * Note: This doesn't "verify" the key yet (that happens when we try to decrypt data).
   * @param {string} password
   * @param {Buffer} salt
   */
  async unlock(password, salt) {
    try {
      this.masterKey = await this.deriveKey(password, salt);
      return true;
    } catch (e) {
      console.error("Key derivation failed:", e);
      return false;
    }
  }

  /**
   * Locks the vault and zeroizes the key in memory.
   */
  lock() {
    if (this.masterKey) {
      // Overwrite memory before nullifying
      try {
        this.masterKey.fill(0);
      } catch (e) {
        // buffer might be immutable or already gone
      }
      this.masterKey = null;
    }
  }

  /**
   * Encrypts plaintext data.
   * @param {string|Object} data - Data to encrypt
   * @returns {Object} { iv, content, tag }
   */
  encrypt(data) {
    if (!this.masterKey) throw new Error("Vault locked.");

    const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
    const iv = crypto.randomBytes(12); // GCM standard IV length is 12 bytes
    const cipher = crypto.createCipheriv(ALGORITHM, this.masterKey, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const tag = cipher.getAuthTag();

    return {
      iv: iv.toString('hex'),
      content: encrypted,
      tag: tag.toString('hex')
    };
  }

  /**
   * Decrypts data.
   * @param {string} ivHex
   * @param {string} contentHex
   * @param {string} tagHex
   * @returns {any} Original data (parsed JSON or string)
   */
  decrypt(ivHex, contentHex, tagHex) {
    if (!this.masterKey) throw new Error("Vault locked.");

    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, this.masterKey, iv);

    decipher.setAuthTag(tag);

    let decrypted = decipher.update(contentHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8'); // Will throw if auth tag mismatch

    try {
      return JSON.parse(decrypted);
    } catch (e) {
      return decrypted;
    }
  }

  isUnlocked() {
    return !!this.masterKey;
  }
}

module.exports = new VaultCryptoEngine();
