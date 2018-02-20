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
  var kmsDecrypt, kmsEncrypt, randomKey, secretKey;
  ({
    randomKey,
    encrypt: kmsEncrypt,
    decrypt: kmsDecrypt
  } = kms);
  // Uses NaCl secret key encryption API.
  return secretKey = function () {
    var decrypt, encrypt, keyLength, nonceLength;
    // Length in bytes
    keyLength = 32;
    nonceLength = 24;
    encrypt = (() => {
      var _ref = _asyncToGenerator(function* (message, encoding = "utf8") {
        var ciphertext, input, key, lockedKey, nonce, random;
        // Get key + nonce from KMS's robust source of entropy.
        random = yield randomKey(keyLength + nonceLength, "buffer");
        key = random.slice(0, keyLength - 1);
        nonce = random.slice(keyLength);
        // Encrypt the message.
        if (encoding === "buffer") {
          input = message;
        } else {
          input = Buffer.from(message, encoding);
        }
        ciphertext = _tweetnacl2.default.secretbox(input, nonce, key);
        // Lock the key
        lockedKey = yield kmsEncrypt(kmsKey, key, "buffer");
        // Return a package to the outer layer.
        return Buffer.from(JSON.stringify({
          message: ciphertext,
          nonce: nonce,
          key: lockedKey
        })).toString("base64");
      });

      return function encrypt(_x) {
        return _ref.apply(this, arguments);
      };
    })();
    decrypt = (() => {
      var _ref2 = _asyncToGenerator(function* (ciphertext, encoding = "utf8") {
        var key, lockedKey, message, nonce;
        ({
          // Extract data for decryption.
          message,
          nonce,
          key: lockedKey
        } = JSON.parse(Buffer.from(ciphertext, "base64").toString()));
        // Unlock the key
        key = yield kmsDecrypt(lockedKey, "buffer");
        // Return the decrypted the message.
        if (encoding === "buffer") {
          return _tweetnacl2.default.secretbox.open(message, nonce, key);
        } else {
          return _tweetnacl2.default.secretbox.open(message, nonce, key).toString(encoding);
        }
      });

      return function decrypt(_x2) {
        return _ref2.apply(this, arguments);
      };
    })();
    return { encrypt, decrypt };
  };
};

exports.default = NaCl;