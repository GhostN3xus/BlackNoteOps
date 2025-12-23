const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs-extra');
const cryptoEngine = require('../security/crypto-engine');

class DBManager {
  constructor() {
    this.db = null;
    this.dbPath = path.join(process.cwd(), 'vault.data');
  }

  isOpen() {
    return !!this.db;
  }

  /**
   * Initializes the DB file and metadata table if needed.
   */
  _initDB() {
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');

    // Create tables
    // vault_meta: stores the SALT (plaintext, public) and a VERIFIER (encrypted)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_meta (
        key TEXT PRIMARY KEY,
        value TEXT
      );

      CREATE TABLE IF NOT EXISTS notes (
        id TEXT PRIMARY KEY,
        iv TEXT,
        data TEXT,
        auth_tag TEXT,
        updated_at INTEGER
      );
    `);
  }

  /**
   * Creates a NEW vault.
   * @param {string} password
   */
  async createVault(password) {
    if (fs.existsSync(this.dbPath)) {
      throw new Error("Vault already exists.");
    }

    this._initDB();

    const salt = cryptoEngine.generateSalt();

    // Unlock engine (generate master key)
    await cryptoEngine.unlock(password, salt);

    // Create a verifier token to test decryption later
    const verifier = cryptoEngine.encrypt({ check: "VERIFIED" });

    const stmt = this.db.prepare('INSERT INTO vault_meta (key, value) VALUES (?, ?)');
    const insertMeta = this.db.transaction(() => {
      stmt.run('salt', salt.toString('hex'));
      stmt.run('verifier_iv', verifier.iv);
      stmt.run('verifier_data', verifier.content);
      stmt.run('verifier_tag', verifier.tag);
    });

    insertMeta();
    return true;
  }

  /**
   * Opens an existing vault.
   * @param {string} password
   */
  async openVault(password) {
    if (!fs.existsSync(this.dbPath)) {
      throw new Error("Vault not found.");
    }

    if (!this.db) {
      this._initDB();
    }

    // Read Salt
    const row = this.db.prepare('SELECT value FROM vault_meta WHERE key = ?').get('salt');
    if (!row) throw new Error("Corrupted Vault: No Salt found.");

    const salt = Buffer.from(row.value, 'hex');

    // Attempt to derive key
    await cryptoEngine.unlock(password, salt);

    // Verify Integrity
    try {
      const iv = this.db.prepare('SELECT value FROM vault_meta WHERE key = ?').get('verifier_iv').value;
      const data = this.db.prepare('SELECT value FROM vault_meta WHERE key = ?').get('verifier_data').value;
      const tag = this.db.prepare('SELECT value FROM vault_meta WHERE key = ?').get('verifier_tag').value;

      const result = cryptoEngine.decrypt(iv, data, tag);

      if (result.check !== "VERIFIED") {
        throw new Error("Decryption result invalid");
      }
      return true;

    } catch (e) {
      cryptoEngine.lock(); // Panic lock
      console.error("Access Denied: Signature Mismatch or Wrong Password.");
      throw new Error("Access Denied: Invalid Credentials or Device mismatch.");
    }
  }

  saveNote(id, contentObj) {
    if (!cryptoEngine.isUnlocked()) throw new Error("Vault locked");

    const encrypted = cryptoEngine.encrypt(contentObj);
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO notes (id, iv, data, auth_tag, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(id, encrypted.iv, encrypted.content, encrypted.tag, Date.now());
  }

  getNote(id) {
    if (!cryptoEngine.isUnlocked()) throw new Error("Vault locked");

    const row = this.db.prepare('SELECT * FROM notes WHERE id = ?').get(id);
    if (!row) return null;

    return cryptoEngine.decrypt(row.iv, row.data, row.auth_tag);
  }

  getAllNotes() {
    if (!cryptoEngine.isUnlocked()) throw new Error("Vault locked");
    const rows = this.db.prepare('SELECT id, iv, data, auth_tag, updated_at FROM notes').all();

    return rows.map(row => {
        try {
            const content = cryptoEngine.decrypt(row.iv, row.data, row.auth_tag);
            return { id: row.id, content, updated_at: row.updated_at };
        } catch(e) {
            return { id: row.id, error: "Decryption Failed" };
        }
    });
  }

  close() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    cryptoEngine.lock();
  }
}

module.exports = new DBManager();
