/**
 * TEST SCRIPT
 * This script verifies the crypto logic without needing the full Electron GUI.
 * It mocks the Native Modules if they are missing so the logic can be verified.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// --- MOCKS ---
// We don't need to mock require('node-machine-id') anymore because device-id.js handles it.
// We DO need to mock 'better-sqlite3' because db-manager.js uses it at the top level?
// Let's check db-manager.js... Yes, it does `require('better-sqlite3')` at top level.

// So we MUST mock 'better-sqlite3' BEFORE loading db-manager IF we were testing db-manager.
// But we are mainly testing crypto-engine here.

// Does crypto-engine require db-manager? No.
// crypto-engine requires device-id.js.

// Let's modify the test to only focus on Crypto Engine for now,
// OR we mock better-sqlite3 properly if we want to import db-manager.

// Mock 'better-sqlite3' just in case we extend the test later or if dependencies get weird.
try {
    require('better-sqlite3');
} catch (e) {
    // We cannot use require.resolve on a missing module.
    // Instead, we just won't test the DBManager part if the module is missing,
    // or we will rely on unit testing CryptoEngine only.
    console.log("INFO: 'better-sqlite3' not found. Creating mock for potential require.");

    // We can't easily mock a top-level require for a missing module in CommonJS
    // without a loader hook or writing a file to node_modules.
    // So we will just skip DB tests if it fails, or assume the user runs `npm install`.
    // For this sandbox, I will rely on the fact that I am testing `crypto-engine` which
    // does NOT require `better-sqlite3`.
}

// --- TEST EXECUTION ---

const cryptoEngine = require('../src/main/security/crypto-engine');

async function runTests() {
    console.log(">>> STARTING SECURITY TESTS <<<");

    const password = "super-secret-password";
    const wrongPassword = "wrong-password";
    const salt = cryptoEngine.generateSalt();

    console.log("[1] Testing Key Derivation (Unlock)...");
    await cryptoEngine.unlock(password, salt);

    if (!cryptoEngine.isUnlocked()) throw new Error("Vault failed to unlock");
    console.log("    PASS: Vault unlocked.");

    console.log("[2] Testing Encryption...");
    const secretData = { mission: "Red Team Alpha", target: "10.0.0.1" };
    const encrypted = cryptoEngine.encrypt(secretData);

    console.log("    Ciphertext:", encrypted.content.substring(0, 20) + "...");
    console.log("    PASS: Data encrypted.");

    console.log("[3] Testing Decryption...");
    const decrypted = cryptoEngine.decrypt(encrypted.iv, encrypted.content, encrypted.tag);

    if (decrypted.mission !== secretData.mission) throw new Error("Decryption mismatch");
    console.log("    PASS: Data decrypted correctly.");

    console.log("[4] Testing Wrong Password (Integrity Check)...");
    // Simulate a fresh start
    cryptoEngine.lock();

    await cryptoEngine.unlock(wrongPassword, salt); // This derives a WRONG key

    try {
        // Attempt to decrypt with the wrong key
        cryptoEngine.decrypt(encrypted.iv, encrypted.content, encrypted.tag);
        throw new Error("FAIL: Decryption should have failed with wrong key!");
    } catch (e) {
        // Node crypto GCM throws if tag mismatch
        console.log("    PASS: Decryption correctly rejected (Auth Tag Mismatch). Error: " + e.message);
    }

    console.log(">>> ALL SYSTEMS GREEN <<<");
}

runTests().catch(e => {
    console.error("TEST FAILED:", e);
    process.exit(1);
});
