import nacl from "tweetnacl"

NaCl = (kms, kmsKey) ->
  {randomKey, encrypt:kmsEncrypt, decrypt:kmsDecrypt} = kms

  # Uses NaCl secret key encryption API.
  secretBox = do ->
    # Length in bytes
    keyLength = 32
    nonceLength = 24

    encrypt = (message, encoding="utf8") ->
      # Get key + nonce from KMS's robust source of entropy.
      random = await randomKey (keyLength + nonceLength), "buffer"
      key = random.slice 0, keyLength
      nonce = random.slice keyLength

      # Encrypt the message. Convert from UInt8Array to Buffer.
      if encoding == "buffer"
        input = message
      else
        input = Buffer.from message, encoding
      ciphertext = Buffer.from nacl.secretbox input, nonce, key

      # Lock the key
      lockedKey = await kmsEncrypt kmsKey, key, "buffer"

      # Return a blob of base64 to the outer layer.
      Buffer.from JSON.stringify {ciphertext, nonce, lockedKey}
      .toString("base64")

    decrypt = (blob, encoding="utf8") ->
      # Extract data from the blob decryption.
      {ciphertext, nonce, lockedKey} =
        JSON.parse Buffer.from(blob, "base64").toString()
      ciphertext = Buffer.from ciphertext.data
      nonce = Buffer.from nonce.data

      # Unlock the key.
      key = await kmsDecrypt lockedKey, "buffer"

      # Return the decrypted the message.
      if encoding == "buffer"
        Buffer.from nacl.secretbox.open ciphertext, nonce, key
      else
        Buffer.from nacl.secretbox.open(ciphertext, nonce, key)
        .toString encoding

    {encrypt, decrypt}

  {secretBox}

export default NaCl
