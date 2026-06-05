"use strict";
/**
 * @ppabari/encryptix — Complete Crypto Toolkit
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.base32Decode = exports.base32Encode = exports.decryptBatchSafe = exports.encryptBatchSafe = exports.decryptBatchMixed = exports.encryptBatchMixed = exports.decryptBatch = exports.encryptBatch = exports.CHARSETS = exports.securePassphrase = exports.secureRandomShuffle = exports.secureRandomSample = exports.secureRandomChoice = exports.secureRandomString = exports.secureRandomFloat = exports.secureRandomInt = exports.secureRandomBytes = exports.verifyHmac = exports.hmac = exports.hash = exports.generateUUID = exports.generateApiKey = exports.generateToken = exports.removeRecipient = exports.addRecipient = exports.multiRecipientDecrypt = exports.multiRecipientEncrypt = exports.fromBase32 = exports.toBase32 = exports.totpKeyUri = exports.generateHOTP = exports.verifyTOTP = exports.generateTOTP = exports.generateTOTPSecret = exports.deriveKeyFromPassword = exports.ecdsaVerify = exports.ecdsaSign = exports.generateECDSAKeyPair = exports.deriveSharedSecret = exports.generateECDHKeyPair = exports.rsaPssVerify = exports.rsaPssSign = exports.generateRSAPSSKeyPair = exports.rsaDecrypt = exports.rsaEncrypt = exports.generateRSAKeyPair = exports.generateMasterKey = exports.EncryptixError = exports.createEncryptix = exports.EncryptixClient = void 0;
exports.deserializeKey = exports.serializeKey = exports.importKeyFromJWK = exports.exportKeyToJWK = exports.reEncryptBatch = exports.reEncrypt = exports.createKeyMetadataStore = exports.withZeroize = exports.zeroizeAll = exports.zeroize = exports.inspectToken = exports.inspectStreamHeader = exports.inspectPayload = exports.convertEncoding = exports.safeCompare = exports.base64Decode = exports.base64urlEncode = exports.base64Encode = exports.hexDecode = exports.hexEncode = void 0;
// Client & factory
var client_js_1 = require("./client.js");
Object.defineProperty(exports, "EncryptixClient", { enumerable: true, get: function () { return client_js_1.EncryptixClient; } });
Object.defineProperty(exports, "createEncryptix", { enumerable: true, get: function () { return client_js_1.createEncryptix; } });
// Errors
var errors_js_1 = require("./utils/errors.js");
Object.defineProperty(exports, "EncryptixError", { enumerable: true, get: function () { return errors_js_1.EncryptixError; } });
// Key management
var keys_js_1 = require("./utils/keys.js");
Object.defineProperty(exports, "generateMasterKey", { enumerable: true, get: function () { return keys_js_1.generateMasterKey; } });
// Algorithms — symmetric
var rsa_js_1 = require("./algorithms/rsa.js");
Object.defineProperty(exports, "generateRSAKeyPair", { enumerable: true, get: function () { return rsa_js_1.generateRSAKeyPair; } });
Object.defineProperty(exports, "rsaEncrypt", { enumerable: true, get: function () { return rsa_js_1.rsaEncrypt; } });
Object.defineProperty(exports, "rsaDecrypt", { enumerable: true, get: function () { return rsa_js_1.rsaDecrypt; } });
var rsa_sign_js_1 = require("./algorithms/rsa-sign.js");
Object.defineProperty(exports, "generateRSAPSSKeyPair", { enumerable: true, get: function () { return rsa_sign_js_1.generateRSAPSSKeyPair; } });
Object.defineProperty(exports, "rsaPssSign", { enumerable: true, get: function () { return rsa_sign_js_1.rsaPssSign; } });
Object.defineProperty(exports, "rsaPssVerify", { enumerable: true, get: function () { return rsa_sign_js_1.rsaPssVerify; } });
var ecdh_js_1 = require("./algorithms/ecdh.js");
Object.defineProperty(exports, "generateECDHKeyPair", { enumerable: true, get: function () { return ecdh_js_1.generateECDHKeyPair; } });
Object.defineProperty(exports, "deriveSharedSecret", { enumerable: true, get: function () { return ecdh_js_1.deriveSharedSecret; } });
Object.defineProperty(exports, "generateECDSAKeyPair", { enumerable: true, get: function () { return ecdh_js_1.generateECDSAKeyPair; } });
Object.defineProperty(exports, "ecdsaSign", { enumerable: true, get: function () { return ecdh_js_1.ecdsaSign; } });
Object.defineProperty(exports, "ecdsaVerify", { enumerable: true, get: function () { return ecdh_js_1.ecdsaVerify; } });
var password_js_1 = require("./algorithms/password.js");
Object.defineProperty(exports, "deriveKeyFromPassword", { enumerable: true, get: function () { return password_js_1.deriveKeyFromPassword; } });
var otp_js_1 = require("./algorithms/otp.js");
Object.defineProperty(exports, "generateTOTPSecret", { enumerable: true, get: function () { return otp_js_1.generateTOTPSecret; } });
Object.defineProperty(exports, "generateTOTP", { enumerable: true, get: function () { return otp_js_1.generateTOTP; } });
Object.defineProperty(exports, "verifyTOTP", { enumerable: true, get: function () { return otp_js_1.verifyTOTP; } });
Object.defineProperty(exports, "generateHOTP", { enumerable: true, get: function () { return otp_js_1.generateHOTP; } });
Object.defineProperty(exports, "totpKeyUri", { enumerable: true, get: function () { return otp_js_1.totpKeyUri; } });
Object.defineProperty(exports, "toBase32", { enumerable: true, get: function () { return otp_js_1.toBase32; } });
Object.defineProperty(exports, "fromBase32", { enumerable: true, get: function () { return otp_js_1.fromBase32; } });
var multi_recipient_js_1 = require("./algorithms/multi-recipient.js");
Object.defineProperty(exports, "multiRecipientEncrypt", { enumerable: true, get: function () { return multi_recipient_js_1.multiRecipientEncrypt; } });
Object.defineProperty(exports, "multiRecipientDecrypt", { enumerable: true, get: function () { return multi_recipient_js_1.multiRecipientDecrypt; } });
Object.defineProperty(exports, "addRecipient", { enumerable: true, get: function () { return multi_recipient_js_1.addRecipient; } });
Object.defineProperty(exports, "removeRecipient", { enumerable: true, get: function () { return multi_recipient_js_1.removeRecipient; } });
// Utilities
var tokens_js_1 = require("./utils/tokens.js");
Object.defineProperty(exports, "generateToken", { enumerable: true, get: function () { return tokens_js_1.generateToken; } });
Object.defineProperty(exports, "generateApiKey", { enumerable: true, get: function () { return tokens_js_1.generateApiKey; } });
Object.defineProperty(exports, "generateUUID", { enumerable: true, get: function () { return tokens_js_1.generateUUID; } });
Object.defineProperty(exports, "hash", { enumerable: true, get: function () { return tokens_js_1.hash; } });
Object.defineProperty(exports, "hmac", { enumerable: true, get: function () { return tokens_js_1.hmac; } });
Object.defineProperty(exports, "verifyHmac", { enumerable: true, get: function () { return tokens_js_1.verifyHmac; } });
var random_js_1 = require("./utils/random.js");
Object.defineProperty(exports, "secureRandomBytes", { enumerable: true, get: function () { return random_js_1.secureRandomBytes; } });
Object.defineProperty(exports, "secureRandomInt", { enumerable: true, get: function () { return random_js_1.secureRandomInt; } });
Object.defineProperty(exports, "secureRandomFloat", { enumerable: true, get: function () { return random_js_1.secureRandomFloat; } });
Object.defineProperty(exports, "secureRandomString", { enumerable: true, get: function () { return random_js_1.secureRandomString; } });
Object.defineProperty(exports, "secureRandomChoice", { enumerable: true, get: function () { return random_js_1.secureRandomChoice; } });
Object.defineProperty(exports, "secureRandomSample", { enumerable: true, get: function () { return random_js_1.secureRandomSample; } });
Object.defineProperty(exports, "secureRandomShuffle", { enumerable: true, get: function () { return random_js_1.secureRandomShuffle; } });
Object.defineProperty(exports, "securePassphrase", { enumerable: true, get: function () { return random_js_1.securePassphrase; } });
Object.defineProperty(exports, "CHARSETS", { enumerable: true, get: function () { return random_js_1.CHARSETS; } });
var batch_js_1 = require("./utils/batch.js");
Object.defineProperty(exports, "encryptBatch", { enumerable: true, get: function () { return batch_js_1.encryptBatch; } });
Object.defineProperty(exports, "decryptBatch", { enumerable: true, get: function () { return batch_js_1.decryptBatch; } });
Object.defineProperty(exports, "encryptBatchMixed", { enumerable: true, get: function () { return batch_js_1.encryptBatchMixed; } });
Object.defineProperty(exports, "decryptBatchMixed", { enumerable: true, get: function () { return batch_js_1.decryptBatchMixed; } });
Object.defineProperty(exports, "encryptBatchSafe", { enumerable: true, get: function () { return batch_js_1.encryptBatchSafe; } });
Object.defineProperty(exports, "decryptBatchSafe", { enumerable: true, get: function () { return batch_js_1.decryptBatchSafe; } });
var codec_js_1 = require("./utils/codec.js");
Object.defineProperty(exports, "base32Encode", { enumerable: true, get: function () { return codec_js_1.base32Encode; } });
Object.defineProperty(exports, "base32Decode", { enumerable: true, get: function () { return codec_js_1.base32Decode; } });
Object.defineProperty(exports, "hexEncode", { enumerable: true, get: function () { return codec_js_1.hexEncode; } });
Object.defineProperty(exports, "hexDecode", { enumerable: true, get: function () { return codec_js_1.hexDecode; } });
Object.defineProperty(exports, "base64Encode", { enumerable: true, get: function () { return codec_js_1.base64Encode; } });
Object.defineProperty(exports, "base64urlEncode", { enumerable: true, get: function () { return codec_js_1.base64urlEncode; } });
Object.defineProperty(exports, "base64Decode", { enumerable: true, get: function () { return codec_js_1.base64Decode; } });
Object.defineProperty(exports, "safeCompare", { enumerable: true, get: function () { return codec_js_1.safeCompare; } });
Object.defineProperty(exports, "convertEncoding", { enumerable: true, get: function () { return codec_js_1.convertEncoding; } });
var inspect_js_1 = require("./utils/inspect.js");
Object.defineProperty(exports, "inspectPayload", { enumerable: true, get: function () { return inspect_js_1.inspectPayload; } });
Object.defineProperty(exports, "inspectStreamHeader", { enumerable: true, get: function () { return inspect_js_1.inspectStreamHeader; } });
Object.defineProperty(exports, "inspectToken", { enumerable: true, get: function () { return inspect_js_1.inspectToken; } });
var zeroize_js_1 = require("./utils/zeroize.js");
Object.defineProperty(exports, "zeroize", { enumerable: true, get: function () { return zeroize_js_1.zeroize; } });
Object.defineProperty(exports, "zeroizeAll", { enumerable: true, get: function () { return zeroize_js_1.zeroizeAll; } });
Object.defineProperty(exports, "withZeroize", { enumerable: true, get: function () { return zeroize_js_1.withZeroize; } });
Object.defineProperty(exports, "createKeyMetadataStore", { enumerable: true, get: function () { return zeroize_js_1.createKeyMetadataStore; } });
Object.defineProperty(exports, "reEncrypt", { enumerable: true, get: function () { return zeroize_js_1.reEncrypt; } });
Object.defineProperty(exports, "reEncryptBatch", { enumerable: true, get: function () { return zeroize_js_1.reEncryptBatch; } });
Object.defineProperty(exports, "exportKeyToJWK", { enumerable: true, get: function () { return zeroize_js_1.exportKeyToJWK; } });
Object.defineProperty(exports, "importKeyFromJWK", { enumerable: true, get: function () { return zeroize_js_1.importKeyFromJWK; } });
Object.defineProperty(exports, "serializeKey", { enumerable: true, get: function () { return zeroize_js_1.serializeKey; } });
Object.defineProperty(exports, "deserializeKey", { enumerable: true, get: function () { return zeroize_js_1.deserializeKey; } });
//# sourceMappingURL=index.js.map