/* jshint node:true */
'use strict';

var test = require('tape');
var nacl = require('tweetnacl/nacl-fast');
var naclStream = require('../nacl-stream').stream;
var byteSequence = require('./utils').byteSequence;

var MAX_CHUNK_LENGTH = 65535;

test('stream', function(t) {
  var i, j, isLast;
  var key = byteSequence(32);
  var nonce = byteSequence(16);
  var data = byteSequence(1024*1024+111);

  // Encrypt.
  var encryptedChunks = [];
  var e = naclStream.createEncryptor(key, nonce);
  for (i = 0; i < data.length; i += MAX_CHUNK_LENGTH) {
    var chunkLen = Math.min(MAX_CHUNK_LENGTH, data.length - i);
    isLast = (data.length - i - chunkLen === 0);
    var ec = e.encryptChunk(data.subarray(i, i+chunkLen), isLast);
    encryptedChunks.push(ec);
  }
  /*// debugging
  encryptedChunks.forEach(function(chunk) {
    console.log((new Buffer(chunk)).toString('hex'));
  });
  */
  t.throws(function() { e.encryptChunk(data.subarray(0, 1000)); }, Error, 'should throw if encryptChunk was called after the last chunk');
  e.clean();

  // Decrypt.
  function decryptChunks(chunks) {
    var decryptedChunks = [];
    var d = naclStream.createDecryptor(key, nonce);
    for (i = 0; i < chunks.length; i++) {
      isLast = (i === chunks.length - 1);
      var dc = d.decryptChunk(chunks[i], isLast);
      if (!dc) return null;
      decryptedChunks.push(dc);
    }
    t.throws(function() { d.decryptChunk(chunks[0]); }, Error, 'should throw if decryptChunk called after last chunk');
    d.clean();
    return decryptedChunks;
  }

  // Compare.
  function compareChunksWithData(chunks) {
    var pos = 0;
    for (i = 0; i < chunks.length; i++) {
      var c = chunks[i];
      for (j = 0; j < c.length; j++, pos++) {
        if (c[j] != data[pos]) return false;
      }
    }
    return true;
  }

  var decryptedChunks = decryptChunks(encryptedChunks);
  t.ok(decryptedChunks, 'should decrypt chunks');
  t.equal(decryptedChunks.length, encryptedChunks.length, 'number of decrypted chunks should be equal to encrypted');
  t.ok(compareChunksWithData(decryptedChunks), 'decrypted data should be equal to original');

  // Drop last chunk.
  var badEncryptedChunks = [];
  for (i = 0; i < encryptedChunks.length-1; i++) badEncryptedChunks.push(encryptedChunks[i]);
  t.notOk(!!decryptChunks(badEncryptedChunks), 'should not decrypt when missing last chunk');

  // Drop first chunk.
  badEncryptedChunks = [];
  for (i = 1; i < encryptedChunks.length; i++) badEncryptedChunks.push(encryptedChunks[i]);
  t.notOk(!!decryptChunks(badEncryptedChunks), 'should not decrypt when missing first chunk');

  // Drop second chunk.
  badEncryptedChunks = [];
  for (i = 0; i < encryptedChunks.length; i++) if (i !== 1) badEncryptedChunks.push(encryptedChunks[i]);
  t.notOk(!!decryptChunks(badEncryptedChunks), 'should not decrypt when missing second chunk');

  t.end();

});
