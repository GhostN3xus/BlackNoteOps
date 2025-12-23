const os = require('os');
const crypto = require('crypto');

let machineIdSync;
try {
  machineIdSync = require('node-machine-id').machineIdSync;
} catch (e) {
  // Module not found or failed to load
  machineIdSync = null;
}

/**
 * Generates a unique Device Fingerprint based on hardware and OS traits.
 * This is crucial for the "Device Binding" feature.
 */
function getDeviceFingerprint() {
  try {
    // 1. Machine ID (Persistent UUID generated at OS install)
    let id = '';
    if (machineIdSync) {
      try {
        id = machineIdSync();
      } catch (e) {
        id = 'fallback-machine-id-' + os.hostname();
      }
    } else {
        // Fallback if module is missing (e.g. during initial dev/test without npm install)
        console.warn("WARNING: 'node-machine-id' missing. Using weak fingerprint for dev/testing.");
        id = 'DEV-ENV-ID-' + os.hostname();
    }

    // 2. User Info (Binds to the specific OS user)
    const userInfo = os.userInfo().username;

    // 3. Platform Architecture (Prevents simple VM migrations sometimes)
    const platform = os.platform() + '-' + os.arch();

    // Combine all factors
    const rawFingerprint = `${id}|${userInfo}|${platform}`;

    // Return a stable hash of the fingerprint
    return crypto.createHash('sha256').update(rawFingerprint).digest('hex');
  } catch (error) {
    console.error('CRITICAL: Failed to generate device fingerprint.', error);
    throw new Error('Security Violation: Device identity could not be established.');
  }
}

module.exports = { getDeviceFingerprint };
