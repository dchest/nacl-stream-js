'use strict';

function byteSequence(len) {
  var a = new Uint8Array(len);
  for (var i = 0; i < a.length; i++) a[i] = i & 0xff;
  return a;
}

module.exports = {
  byteSequence: byteSequence
}
