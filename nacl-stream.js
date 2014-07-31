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

  var DEFAULT_MAX_CHUNK = 65535;

  var ZEROBYTES = nacl.lowlevel.crypto_secretbox_ZEROBYTES;
  var BOXZEROBYTES = nacl.lowlevel.crypto_secretbox_BOXZEROBYTES;
  var crypto_core_hsalsa20 = nacl.lowlevel.crypto_core_hsalsa20;
  var crypto_stream_salsa20 = nacl.lowlevel.crypto_stream_salsa20;
  var crypto_stream_salsa20_xor = nacl.lowlevel.crypto_stream_salsa20_xor;
  var crypto_onetimeauth = nacl.lowlevel.crypto_onetimeauth;
  var crypto_onetimeauth_verify = nacl.lowlevel.crypto_onetimeauth_verify;

  function incrementChunkCounter(ctr) {
    for (var i = 0; i < 8; i++) {
      ctr[i]++;
      if (ctr[i]) break;
    }
  }

  function setLastChunkFlag(ctr) {
    ctr[7] |= 0x80;
  }

  function clean() {
    for (var i = 0; i < arguments.length; i++) {
      var arg = arguments[i];
      for (var j = 0; j < arg.length; j++) arg[j] = 0;
    }
  }

  function readChunkLength(data, offset) {
    offset |= 0;
    if (data.length < offset + 4) return -1;
    return data[offset] | data[offset+1] << 8 |
           data[offset+2] << 16 | data[offset+3] << 24;
  }

  function checkArgs(key, nonce, maxChunkLength) {
    if (key.length !== 32) throw new Error('bad key length, must be 32 bytes');
    if (nonce.length !== 16) throw new Error('bad nonce length, must be 16 bytes');
    if (maxChunkLength >= 0xffffffff) throw new Error('max chunk length is too large');
    if (maxChunkLength < 16) throw new Error('max chunk length is too small');
  }

  // constant for hsalsa20, "expand 32-byte k"
  var SIGMA = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);

  // Derives a 32-byte XSalsa20 subkey from 32-byte key and 16-byte nonce.
  function deriveSubkey(key, nonce) {
    var subkey = new Uint8Array(32);
    crypto_core_hsalsa20(subkey, nonce, key, SIGMA);
    return subkey;
  }

  // crypto_secretbox_subkey is like NaCl's crypto_secretbox,
  // but uses pre-derived XSalsa20 subkey.
  function crypto_secretbox_subkey(c,m,d,n,subkey) {
    var i;
    if (d < 32) return -1;
    crypto_stream_salsa20_xor(c,0,m,0,d,n,subkey);
    crypto_onetimeauth(c, 16, c, 32, d - 32, c);
    for (i = 0; i < 16; i++) c[i] = 0;
    return 0;
  }

  // crypto_secretbox_subkey_open is like NaCl's crypto_secretbox_open,
  // but uses pre-derived XSalsa20 subkey.
  function crypto_secretbox_subkey_open(m,c,d,n,subkey) {
    var i;
    var x = new Uint8Array(32);
    if (d < 32) return -1;
    crypto_stream_salsa20(x,0,32,n,subkey);
    if (crypto_onetimeauth_verify(c, 16,c, 32,d - 32,x) !== 0) return -1;
    crypto_stream_salsa20_xor(m,0,c,0,d,n,subkey);
    for (i = 0; i < 32; i++) m[i] = 0;
    return 0;
  }

  function StreamEncryptor(key, nonce, maxChunkLength) {
    checkArgs(key, nonce, maxChunkLength);
    this._subkey = deriveSubkey(key, nonce);
    this._chunkCounter = new Uint8Array(8);
    this._maxChunkLength = maxChunkLength || DEFAULT_MAX_CHUNK;
    this._in = new Uint8Array(ZEROBYTES + this._maxChunkLength);
    this._out = new Uint8Array(ZEROBYTES + this._maxChunkLength);
    this._done = false;
  }

  StreamEncryptor.prototype.encryptChunk = function(chunk, isLast) {
    if (this._done) throw new Error('called encryptChunk after last chunk');
    var chunkLen = chunk.length;
    if (chunkLen > this._maxChunkLength)
      throw new Error('chunk is too large: ' + chunkLen + ' / ' + this._maxChunkLength);
    for (var i = 0; i < ZEROBYTES; i++) this._in[i] = 0;
    this._in.set(chunk, ZEROBYTES);
    if (isLast) {
      setLastChunkFlag(this._chunkCounter);
      this._done = true;
    }
    crypto_secretbox_subkey(this._out, this._in, chunkLen + ZEROBYTES, this._chunkCounter, this._subkey);
    incrementChunkCounter(this._chunkCounter);
    var encryptedChunk = this._out.subarray(BOXZEROBYTES-4, BOXZEROBYTES-4 + chunkLen+16+4);
    encryptedChunk[0] = (chunkLen >>>  0) & 0xff;
    encryptedChunk[1] = (chunkLen >>>  8) & 0xff;
    encryptedChunk[2] = (chunkLen >>> 16) & 0xff;
    encryptedChunk[3] = (chunkLen >>> 24) & 0xff;
    return new Uint8Array(encryptedChunk);
  };

  StreamEncryptor.prototype.clean = function() {
    clean(this._chunkCounter, this._in, this._out);
  };

  function StreamDecryptor(key, nonce, maxChunkLength) {
    checkArgs(key, nonce, maxChunkLength);
    this._subkey = deriveSubkey(key, nonce);
    this._chunkCounter = new Uint8Array(8);
    this._maxChunkLength = maxChunkLength || DEFAULT_MAX_CHUNK;
    this._in = new Uint8Array(ZEROBYTES + this._maxChunkLength);
    this._out = new Uint8Array(ZEROBYTES + this._maxChunkLength);
    this._failed = false;
    this._done = false;
  }

  StreamDecryptor.prototype._fail = function() {
    this._failed = true;
    this.clean();
    return null;
  };

  StreamDecryptor.prototype.decryptChunk = function(encryptedChunk, isLast) {
    if (this._failed) return null;
    if (this._done) throw new Error('called decryptChunk after last chunk');
    var encryptedChunkLen = encryptedChunk.length;
    if (encryptedChunkLen < 4 + BOXZEROBYTES) return this._fail();
    var chunkLen = readChunkLength(encryptedChunk);
    if (chunkLen < 0 || chunkLen > this._maxChunkLength) return this._fail();
    if (chunkLen + 4 + BOXZEROBYTES !== encryptedChunkLen) return this._fail();
    for (var i = 0; i < BOXZEROBYTES; i++) this._in[i] = 0;
    for (i = 0; i < encryptedChunkLen-4; i++) this._in[BOXZEROBYTES+i] = encryptedChunk[i+4];
    if (isLast) {
      setLastChunkFlag(this._chunkCounter);
      this._done = true;
    }
    if (crypto_secretbox_subkey_open(this._out, this._in, encryptedChunkLen+BOXZEROBYTES-4,
                this._chunkCounter, this._subkey) !== 0) return this._fail();
    incrementChunkCounter(this._chunkCounter);
    return new Uint8Array(this._out.subarray(ZEROBYTES, ZEROBYTES + chunkLen));
  };

  StreamDecryptor.prototype.clean = function() {
    clean(this._chunkCounter, this._in, this._out);
  };

  return {
    createEncryptor: function(k, n, c) { return new StreamEncryptor(k, n, c); },
    createDecryptor: function(k, n, c) { return new StreamDecryptor(k, n, c); },
    readChunkLength: readChunkLength
  };

}));
