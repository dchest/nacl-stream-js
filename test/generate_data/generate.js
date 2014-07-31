var nacl = require('tweetnacl/nacl-fast');
var naclStream = require('../../nacl-stream').stream;
var byteSequence = require('../utils').byteSequence;

function generateTestVector() {
  var i, isLast;
  var key = byteSequence(32);
  var nonce = byteSequence(16);
  var data = byteSequence(100000);
  var maxChunkLen = 32768;
  var buffers = [];

  var e = naclStream.createEncryptor(key, nonce, maxChunkLen);
  for (i = 0; i < data.length; i += maxChunkLen) {
    var chunkLen = Math.min(maxChunkLen, data.length - i);
    isLast = (data.length - i - chunkLen === 0);
    var ec = e.encryptChunk(data.subarray(i, i+chunkLen), isLast);
    buffers.push(new Buffer(ec));
  }
  e.clean();
  process.stdout.write('module.exports = "' + Buffer.concat(buffers).toString('base64') + '";');
}

generateTestVector();
