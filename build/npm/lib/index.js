"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _tweetnacl = require("tweetnacl");

var _tweetnacl2 = _interopRequireDefault(_tweetnacl);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var NaCl;

NaCl = function (kms, kmsKey) {
  var kmsDecrypt, kmsEncrypt, randomKey, secretBox;
  ({
    randomKey,
    encrypt: kmsEncrypt,
    decrypt: kmsDecrypt
  } = kms);
  // Uses NaCl secret key encryption API.
  secretBox = function () {
    var decrypt, encrypt, keyLength, nonceLength;
    // Length in bytes
    keyLength = 32;
    nonceLength = 24;
    encrypt = (() => {
      var _ref = _asyncToGenerator(function* (message, encoding = "utf8") {
        var ciphertext, input, key, lockedKey, nonce, random;
        // Get key + nonce from KMS's robust source of entropy.
        random = yield randomKey(keyLength + nonceLength, "buffer");
        key = random.slice(0, keyLength);
        nonce = random.slice(keyLength);
        // Encrypt the message. Convert from UInt8Array to Buffer.
        if (encoding === "buffer") {
          input = message;
        } else {
          input = Buffer.from(message, encoding);
        }
        ciphertext = Buffer.from(_tweetnacl2.default.secretbox(input, nonce, key));
        // Lock the key
        lockedKey = yield kmsEncrypt(kmsKey, key, "buffer");
        // Return a blob of base64 to the outer layer.
        return Buffer.from(JSON.stringify({ ciphertext, nonce, lockedKey })).toString("base64");
      });

      return function encrypt(_x) {
        return _ref.apply(this, arguments);
      };
    })();
    decrypt = (() => {
      var _ref2 = _asyncToGenerator(function* (blob, encoding = "utf8") {
        var ciphertext, key, lockedKey, nonce;
        // Extract data from the blob decryption.
        ({ ciphertext, nonce, lockedKey } = JSON.parse(Buffer.from(blob, "base64").toString()));
        ciphertext = Buffer.from(ciphertext.data);
        nonce = Buffer.from(nonce.data);
        // Unlock the key.
        key = yield kmsDecrypt(lockedKey, "buffer");
        // Return the decrypted the message.
        if (encoding === "buffer") {
          return Buffer.from(_tweetnacl2.default.secretbox.open(ciphertext, nonce, key));
        } else {
          return Buffer.from(_tweetnacl2.default.secretbox.open(ciphertext, nonce, key)).toString(encoding);
        }
      });

      return function decrypt(_x2) {
        return _ref2.apply(this, arguments);
      };
    })();
    return { encrypt, decrypt };
  }();
  return { secretBox };
};

exports.default = NaCl;