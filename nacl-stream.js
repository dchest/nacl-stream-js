/*
 * nacl-stream: streaming encryption based on TweetNaCl.js
 * Written by Dmitry Chestnykh in 2014. Public domain.
 * <https://github.com/dchest/nacl-stream-js>
 */
(function(root, f) {
  'use strict';
  if (typeof module !== 'undefined' && module.exports) module.exports.stream = f(require('tweetnacl/nacl-fast'));
  else root.nacl.stream = f(root.nacl);

}(this, function(nacl) {
  'use strict';

  if (!nacl) throw new Error('tweetnacl not loaded');

  var MAX_CHUNK_LEN = 65535; // can be set to less, but not more than that.

  var ZEROBYTES = nacl.lowlevel.crypto_secretbox_ZEROBYTES;
  var BOXZEROBYTES = nacl.lowlevel.crypto_secretbox_BOXZEROBYTES;
  var crypto_secretbox = nacl.lowlevel.crypto_secretbox;
  var crypto_secretbox_open = nacl.lowlevel.crypto_secretbox_open;

  function incrementChunkCounter(fullNonce) {
    for (var i = 16; i < 24; i++) {
      fullNonce[i]++;
      if (fullNonce[i]) break;
    }
  }

  function setLastChunkFlag(fullNonce) {
    fullNonce[23] |= 0x80;
  }

  function clean() {
    for (var i = 0; i < arguments.length; i++) {
      var arg = arguments[i];
      for (var j = 0; j < arg.length; j++) arg[j] = 0;
    }
  }

  function checkArgs(key, nonce) {
    if (key.length !== 32) throw new Error('bad key length, must be 32 bytes');
    if (nonce.length !== 16) throw new Error('bad nonce length, must be 16 bytes');
  }

  function StreamEncryptor(key, nonce) {
    checkArgs(key, nonce);
    this._key = key;
    this._fullNonce = new Uint8Array(24);
    this._fullNonce.set(nonce);
    this._in = new Uint8Array(ZEROBYTES + MAX_CHUNK_LEN);
    this._out = new Uint8Array(ZEROBYTES + MAX_CHUNK_LEN);
  }

  StreamEncryptor.prototype.encryptChunk = function(chunk, isLast) {
    var chunkLen = chunk.length;
    if (chunkLen > MAX_CHUNK_LEN) throw new Error('chunk is too large');
    for (var i = 0; i < ZEROBYTES; i++) this._in[i] = 0;
    this._in.set(chunk, ZEROBYTES);
    if (isLast) setLastChunkFlag(this._fullNonce);
    crypto_secretbox(this._out, this._in, chunkLen + ZEROBYTES, this._fullNonce, this._key);
    incrementChunkCounter(this._fullNonce);
    var encryptedChunk = this._out.subarray(BOXZEROBYTES-2, BOXZEROBYTES-2 + chunkLen+16+2);
    encryptedChunk[0] = (chunkLen >>> 0) & 0xff;
    encryptedChunk[1] = (chunkLen >>> 8) & 0xff;
    return encryptedChunk;
  };

  StreamEncryptor.prototype.clean = function() {
    clean(this._fullNonce, this._in, this._out);
  };

  function StreamDecryptor(key, nonce) {
    checkArgs(key, nonce);
    this._key = key;
    this._fullNonce = new Uint8Array(24);
    this._fullNonce.set(nonce);
    this._in = new Uint8Array(ZEROBYTES + MAX_CHUNK_LEN);
    this._out = new Uint8Array(ZEROBYTES + MAX_CHUNK_LEN);
    this._failed = false;
  }

  StreamDecryptor.prototype._fail = function() {
    this._failed = true;
    this.clean();
    return null;
  };

  StreamDecryptor.prototype.readLength = function(data) {
    if (data.length < 2) return -1;
    return data[0] | data[1] << 8;
  };

  StreamDecryptor.prototype.decryptChunk = function(encryptedChunk, isLast) {
    if (this._failed) return null;
    var encryptedChunkLen = encryptedChunk.length;
    if (encryptedChunkLen < 2 + BOXZEROBYTES) return this._fail();
    var chunkLen = this.readLength(encryptedChunk);
    if (chunkLen < 0 || chunkLen > MAX_CHUNK_LEN) return this._fail();
    if (chunkLen + 2 + BOXZEROBYTES !== encryptedChunkLen) return this._fail();
    for (var i = 0; i < BOXZEROBYTES; i++) this._in[i] = 0;
    for (i = 0; i < encryptedChunkLen-2; i++) this._in[BOXZEROBYTES+i] = encryptedChunk[i+2];
    if (isLast) setLastChunkFlag(this._fullNonce);
    if (crypto_secretbox_open(this._out, this._in, encryptedChunkLen+BOXZEROBYTES-2,
                this._fullNonce, this._key) !== 0) return this._fail();
    incrementChunkCounter(this._fullNonce);
    return this._out.subarray(ZEROBYTES, ZEROBYTES + chunkLen);
  };

  StreamDecryptor.prototype.clean = function() {
    clean(this._fullNonce, this._in, this._out);
  };

  return {
    createEncryptor: function(k, n) { return new StreamEncryptor(k, n); },
    createDecryptor: function(k, n) { return new StreamDecryptor(k, n); },
    maxChunkLength: MAX_CHUNK_LEN
  };

}));
