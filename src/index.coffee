import nacl from "tweetnacl"

NaCl = (kms, kmsKey) ->
  {randomKey, encrypt, decrypt} = kms

  # Uses NaCl secret key encryption API.
  secretKey = ->
    # Length in bytes
    keyLength = 32
    nonceLength = 24

    encrypt = (message, encoding="utf8") ->
      # Get key + nonce from KMS's robust source of entropy.
      random = await randomKey (keyLength + nonceLength), "buffer"
      key = random.slice 0, keyLength - 1
      nonce = random.slice keyLength

      # Encrypt the message.
      if encoding == "buffer"
        input = message
      else
        input = Buffer.from message, encoding
      ciphertext = nacl.secretbox input, nonce, key

      # Lock the key
      lockedKey = await encrypt kmsKey, key, "buffer"

      # Return a package to the outer layer.
      Buffer.from JSON.stringify
        message: ciphertext
        nonce: nonce
        key: lockedKey
      .toString("base64")

    decrypt = (ciphertext, encoding) ->
      # Extract data for decryption.
      {message, nonce, key:lockedKey} =
        JSON.parse Buffer.from(ciphertext, "base64").toString()

      # Unlock the key
      key = await decrypt lockedKey, "buffer"

      # Return the decrypted the message.
      nacl.secretbox.open message, nonce, key

    {encrypt, decrypt}

export default NaCl
