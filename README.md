nacl-stream: streaming encryption based on TweetNaCl.js
=======================================================

Written by Dmitry Chestnykh in 2014. Public domain. 
<https://github.com/dchest/nacl-stream-js>

Based on
<https://www.imperialviolet.org/2014/06/27/streamingencryption.html>

[![Build Status](https://travis-ci.org/dchest/nacl-stream-js.svg?branch=master)
](https://travis-ci.org/dchest/nacl-stream-js)

:warning: **ALPHA VERSION! There will be bugs. May change. May break.** :warning:

Format description
------------------

- Inputs: 32-byte key, 16-byte nonce, a stream (or a file).
- Stream is split into chunks of the specified length.
- 24-byte fullNonce is acquired by concatenating 16-byte nonce and 8-byte
  little-endian chunk number.
- Each chunk except for the last one is encrypted like this, starting with
  chunk number 0:
  ```
  fullNonce0 := nonce || 0
  encryptedChunk0 := len(chunk0) || nacl.secretbox(chunk0, fullNonce0, key)
  fullNonce1 := nonce || 1
  encryptedChunk1 := len(chunk1) || nacl.secretbox(chunk1, fullNonce1, key)
  ...
  ```
  where `len(chunk)` is a 4-byte little-endian plaintext chunk length.

- The last chunk's fullNonce has the most significant bit set:
  ```
  fullNonceN := nonce || setMSB(N)
  encryptedChunkN = len(chunkN) || nacl.secretbox(chunkN, fullNonceN, key)
  ```
- Encrypted chunks are concatenated to form the encrypted stream.

Usage
-----

**The API is fairy low-level and should be used as a building block for some
high-level API which would deal with actual streams or files.**

The module provides two constructor functions (in `window.nacl` namespace or as
a CommonJS module):

### stream.createEncryptor(key, nonce, maxChunkLength)

Returns a stream encryptor object using 32-byte key and 16-byte nonce (both of
`Uint8Array` type) and the maximum chunk length with the following methods:

#### *encryptor*.encryptChunk(chunk, isLast)

Encrypts the given `Uint8Array` chunk and returns a new `Uint8Array` array
with encrypted chunk.

If encrypting the last chunk of stream, `isLast` must be set to `true`.

#### *encryptor*.clean()
 
Zeroes out temporary space. Should be called after encrypting all chunks.

### stream.createDecryptor(key, nonce, maxChunkLength)

Returns a stream decryptor object using 32-byte key and 16-byte nonce (both of
`Uint8Array` type) and the maximum chunk length with the following methods:

#### *decryptor*.decryptChunk(encryptedChunk, isLast)

Decrypts the given `Uint8Array` encrypted chunk and returns a new `Uint8Array`
array with decrypted chunk.

The given encryptedChunk should be in the format created by `encryptChunk`,
i.e. prefixed with original chunk length.

Returns `null` if the chunk cannot be decrypted. In this case, futher
calls to `decryptChunk` will deliberately fail: callers should stop trying
to decrypt this stream and, if possible, discard previously decrypted
chunks.

If decrypting the last chunk of stream, `isLast` must be set to `true`.

#### *decryptor*.clean()
 
Zeroes out temporary space. Should be called after decrypting all chunks.

#### stream.readChunkLength(data[, offset])

Reads four bytes from the given offset (or from the beginning, if no offset is
given) of `Uint8Array` data and returns the chunk length. Length of
encryptedChunk passed to `decryptChunk` should be 4 + 16 + *chunkLength* bytes.

