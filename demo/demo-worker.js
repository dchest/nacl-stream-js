'use strict';

var window = self;

importScripts(
  '../node_modules/tweetnacl/nacl-fast.js',
  '../nacl-stream.js'
);

onmessage = function(event) {
  switch (event.data.name) {

    case 'ENCRYPT_START':
      startEncryption(event.data.key, event.data.nonce);
      break;
    case 'ENCRYPT_CHUNK':
      encryptChunk(event.data.chunk, event.data.isLast);
      break;
    case 'ENCRYPT_FINISH':
      finishEncryption();
      break;
    case 'ENCRYPT_CANCEL':
      cancelEncryption(event.data.reason);
      break;

    case 'DECRYPT_START':
      startDecryption(event.data.key, event.data.nonce);
      break;
    case 'DECRYPT_CHUNK':
      decryptChunk(event.data.chunk, event.data.isLast);
      break;
    case 'DECRYPT_FINISH':
      finishDecryption();
      break;
    case 'DECRYPT_CANCEL':
      cancelDecryption(event.data.reason);
      break;

    default:
      throw new Error('worker received unknown message ' + event.data.name);
  }
};

var encryptor = null;

function startEncryption(key, nonce) {
  encryptor = nacl.stream.createEncryptor(key, nonce);
  postMessage({
    name: 'ENCRYPT_START_OK'
  });
}

function encryptChunk(chunk, isLast) {
  var encryptedChunk = encryptor.encryptChunk(chunk, isLast);
  postMessage({
    name: 'ENCRYPT_CHUNK_OK',
    encryptedChunk: encryptedChunk,
    isLast: isLast
  });
}

function finishEncryption() {
  encryptor.clean();
  encryptor = null;
  postMessage({
    name: 'ENCRYPT_FINISH_OK'
  });
}

function cancelEncryption(reason) {
  encryptor.clean();
  encryptor = null;
  postMessage({
    name: 'ENCRYPT_CANCEL_OK',
    reason: reason
  });
}


var decryptor = null;

function startDecryption(key, nonce) {
  decryptor = nacl.stream.createDecryptor(key, nonce);
  postMessage({
    name: 'DECRYPT_START_OK'
  });
}

function decryptChunk(chunk, isLast) {
  var decryptedChunk = decryptor.decryptChunk(chunk, isLast);
  postMessage({
    name: 'DECRYPT_CHUNK_OK',
    decryptedChunk: decryptedChunk,
    isLast: isLast
  });
}

function finishDecryption() {
  decryptor.clean();
  decryptor = null;
  postMessage({
    name: 'DECRYPT_FINISH_OK'
  });
}

function cancelDecryption(reason) {
  decryptor.clean();
  decryptor = null;
  postMessage({
    name: 'DECRYPT_CANCEL_OK',
    reason: reason
  });
}
