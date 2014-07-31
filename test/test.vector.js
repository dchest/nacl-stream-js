/* jshint node:true */
'use strict';

var test = require('tape');
var nacl = require('tweetnacl/nacl-fast');
var naclStream = require('../nacl-stream').stream;
var byteSequence = require('./utils').byteSequence;

var vector = require('./data/vector.js');

function getVectorChunks() {
  var chunks = [];
  var a = nacl.util.decodeBase64(vector);
  var chunkLen = 0;
  for (var i = 0; i < a.length; i += chunkLen + 16 + 4) {
    chunkLen = naclStream.readChunkLength(a, i);
    if (chunkLen < 0) throw new Error('bad chunk length: ' + chunkLen);
    chunks.push(new Uint8Array(a.subarray(i, i + 4 + 16 + chunkLen)));
  }
  return chunks;
}

var vectorChunks = getVectorChunks();
var vectorLength = 100000;
var maxChunkLen = 32768;
var plaintext = byteSequence(vectorLength);

test('encryption (test vector)', function(t) {
  var key = byteSequence(32);
  var nonce = byteSequence(16);
  var data = plaintext;

  var e = naclStream.createEncryptor(key, nonce, maxChunkLen);
  var i, isLast, j = 0;
  for (i = 0; i < data.length; i += maxChunkLen) {
    var chunkLen = Math.min(maxChunkLen, data.length - i);
    isLast = (data.length - i - chunkLen === 0);
    var ec = e.encryptChunk(data.subarray(i, i+chunkLen), isLast);
    t.equal(nacl.util.encodeBase64(ec), nacl.util.encodeBase64(vectorChunks[j]));
    j++;
  }
  t.end();
});

test('decryption (test vector)', function(t) {
  var key = byteSequence(32);
  var nonce = byteSequence(16);
  var chunks = vectorChunks;

  var d = naclStream.createDecryptor(key, nonce, maxChunkLen);
  var isLast, i, j = 0;
  for (i = 0; i < vectorChunks.length; i++) {
    isLast = (i === vectorChunks.length - 1);
    var dc = d.decryptChunk(vectorChunks[i], isLast);
    t.ok(dc, 'decryption should succeed');
    t.equal(nacl.util.encodeBase64(dc), nacl.util.encodeBase64(plaintext.subarray(j, j+dc.length)));
  }
  t.end();
});
