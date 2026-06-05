"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateMasterKey = generateMasterKey;
exports.validateMasterKey = validateMasterKey;
exports.resolveMasterKey = resolveMasterKey;
exports.resolveKeychainKey = resolveKeychainKey;
const env_js_1 = require("./env.js");
const errors_js_1 = require("./errors.js");
/**
 * Generates a cryptographically strong 256-bit (32-byte) master key.
 * Returns a 64-character lowercase hex string.
 *
 * Store this in your environment: ENCRYPTIX_KEY=<output>
 */
function generateMasterKey() {
    const bytes = (0, env_js_1.getCrypto)().getRandomValues(new Uint8Array(32));
    return (0, env_js_1.bytesToHex)(bytes);
}
/**
 * Validates a master key hex string.
 * Must be exactly 64 hex characters (32 bytes / 256 bits).
 */
function validateMasterKey(key) {
    if (typeof key !== 'string') {
        throw new errors_js_1.EncryptixError('INVALID_KEY', 'Encryption key must be a string.');
    }
    if (key.length !== 64) {
        throw new errors_js_1.EncryptixError('INVALID_KEY', `Encryption key must be a 64-character hex string (32 bytes). Got length: ${key.length}.`);
    }
    if (!/^[0-9a-fA-F]+$/.test(key)) {
        throw new errors_js_1.EncryptixError('INVALID_KEY', 'Encryption key must be a valid hex string (0-9, a-f).');
    }
}
/**
 * Resolves the master key from:
 * 1. The explicitly provided value
 * 2. The ENCRYPTIX_KEY environment variable
 * 3. Throws if neither is set
 */
function resolveMasterKey(explicit) {
    const key = explicit ?? (typeof process !== 'undefined' ? process.env.ENCRYPTIX_KEY : undefined);
    if (!key) {
        throw new errors_js_1.EncryptixError('INVALID_KEY', 'No encryption key provided. Pass `key` to EncryptixClient or set the ENCRYPTIX_KEY environment variable.');
    }
    validateMasterKey(key);
    return key;
}
/**
 * Resolves a key from the keychain by version number.
 * Used during decryption with key rotation.
 */
function resolveKeychainKey(keychain, version) {
    const key = keychain[version];
    if (!key) {
        throw new errors_js_1.EncryptixError('KEY_NOT_FOUND', `Key version ${version} not found in keychain. ` +
            `Available versions: [${Object.keys(keychain).join(', ')}]`);
    }
    validateMasterKey(key);
    return key;
}
//# sourceMappingURL=keys.js.map