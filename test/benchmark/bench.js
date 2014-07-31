var test = require('tape');
var nacl = require('tweetnacl/nacl-fast');
var naclStream = require('../../nacl-stream').stream;

var MB = 10;

function benchmark(fn, bytes) {
  var start = new Date();
  var num = MB;
  for (var i = 0; i < num; i++) fn();
  var elapsed = (new Date()) - start;
  console.log(' ' + ((bytes*num/1024/1024*1000)/elapsed).toFixed(3), 'MB/s');
  console.log(' ' + ((num*1000)/elapsed).toFixed(3), 'ops/s');
}

var key = new Uint8Array(32);
var nonce = new Uint8Array(16);
var fullNonce = new Uint8Array(24);
var chunk = new Uint8Array(1024*1024); // 1 MB

function benchmarkSecretbox() {
  console.log('Benchmarking secretbox (no chunking)...');
  var allChunks = new Uint8Array(MB * 1024*1024);
  benchmark(function() {
    nacl.secretbox(allChunks, fullNonce, key);
  }, allChunks.length);
}

function benchmarkEncryptor() {
  console.log('Benchmarking encrypt...');
  var e = naclStream.createEncryptor(key, nonce, chunk.length);
  benchmark(function() {
    e.encryptChunk(chunk);
  }, chunk.length);
}

function benchmarkEncryptorDecryptor() {
  console.log('Benchmarking decrypt(encrypt)...');
  var e = naclStream.createEncryptor(key, nonce, chunk.length);
  var d = naclStream.createDecryptor(key, nonce, chunk.length);
  benchmark(function() {
    d.decryptChunk(e.encryptChunk(chunk));
  }, chunk.length);
}

benchmarkSecretbox();
benchmarkEncryptor();
benchmarkEncryptorDecryptor();
