function encryptBlob(key, nonce, blob, mimeType, doneCallback, errorCallback, progressCallback) {
  // We will collect encrypted chunks in this array:
  var encryptedChunks = [];

  // Position indicates the current byte offset in the blob.
  var position = 0;

  // Create worker.
  var worker = new Worker('demo-worker.js');

  worker.onmessage = function(event) {
    switch (event.data.name) {

      case 'ENCRYPT_START_OK':
        // Encryption started, feed the first chunk to worker.
        postNextChunk();
        break;

      case 'ENCRYPT_CHUNK_OK':
        // A chunk was encrypted, save it...
        encryptedChunks.push(event.data.encryptedChunk);

        // ...and report progress.
        if (progressCallback) progressCallback(position, blob.size);

        if (!event.data.isLast) {
          // Feed the next chunk to worker.
          postNextChunk();
        } else {
          // This chunk was last, so finish encryption.
          worker.postMessage({
            name: 'ENCRYPT_FINISH'
          });
       }
       break;

      case 'ENCRYPT_FINISH_OK':
        // Encryption finished!
        doneCallback(new Blob(encryptedChunks, {type: mimeType}));
        break;

      case 'ENCRYPT_CANCEL_OK':
        // Encryption canceled.
        errorCallback(event.data.reason);
        break;

      default:
        throw new Error('received unknown message from worker ' + event.data.name);
    }
  };

  function error(reason) {
    worker.postMessage({
      name: 'ENCRYPT_CANCEL',
      reason: reason
    });
  }

  // Reads blob slice contents as Uint8Array, passing it to callback.
  function readBlobSlice(blob, start, end, callback) {
    var reader = new FileReader(); //XXX cache reader as the enclosed function's var?
    reader.onerror = function(event) {
      error(event); //TODO where is actual error string?
    };
    reader.onload = function() {
      callback(new Uint8Array(reader.result));
    };
    reader.readAsArrayBuffer(blob.slice(start, end));
  }

  // Feeds next chunk to worker and advances position.
  function postNextChunk() {
    var isLast = false;
    var end = position + 65535;
    if (end >= blob.size) {
      end = blob.size;
      isLast = true;
    }
    readBlobSlice(blob, position, end, function(chunk) {
      worker.postMessage({
        name: 'ENCRYPT_CHUNK',
        chunk: chunk,
        isLast: isLast
      });
      // Advance position.
      position = end;
    });
  }

  // Start encryption!
  worker.postMessage({
    name: 'ENCRYPT_START',
    key: key,
    nonce: nonce
  });
}

function decryptBlob(key, nonce, blob, mimeType, doneCallback, errorCallback, progressCallback) {
  // We will collect decrypted chunks in this array:
  var decryptedChunks = [];

  // Position indicates the current byte offset in the blob.
  var position = 0;

  // Cached next chunk size.
  var nextChunkSize = -1;

  // Create worker.
  var worker = new Worker('demo-worker.js');

  worker.onmessage = function(event) {
    switch (event.data.name) {

      case 'DECRYPT_START_OK':
        // Decryption started, feed the first chunk to worker.
        postNextChunk();
        break;

      case 'DECRYPT_CHUNK_OK':
        // Check if decrypting this chunk succeeded.
        if (!event.data.decryptedChunk) {
          error('decryption failed');
          return;
        }

        // A chunk was decrypted, save it...
        decryptedChunks.push(event.data.decryptedChunk);

        // ...and report progress.
        if (progressCallback) progressCallback(position, blob.size);

        if (!event.data.isLast) {
          // Feed the next chunk to worker.
          postNextChunk();
        } else {
          // This chunk was last, so finish decryption.
          worker.postMessage({
            name: 'DECRYPT_FINISH'
          });
       }
       break;

      case 'DECRYPT_FINISH_OK':
        // Decryption finished!
        doneCallback(new Blob(decryptedChunks, {type: mimeType}));
        break;

      case 'DECRYPT_CANCEL_OK':
        // Decryption canceled.
        errorCallback(event.data.reason);
        break;

      default:
        throw new Error('received unknown message from worker ' + event.data.name);
    }
  };

  // Cancel decryption with error.
  function error(reason) {
    worker.postMessage({
      name: 'DECRYPT_CANCEL',
      reason: reason
    });
  }

  // Reads blob slice contents as Uint8Array, passing it to callback.
  function readBlobSlice(blob, start, end, callback) {
    var reader = new FileReader(); //XXX cache reader as the enclosed function's var?
    reader.onerror = function(event) {
      error(event); //XXX what's the actual error description?
    };
    reader.onload = function() {
      callback(new Uint8Array(reader.result));
    };
    reader.readAsArrayBuffer(blob.slice(start, end));
  }

  // Feeds next chunk to worker and advances position.
  function postNextChunk() {
    if (nextChunkSize === -1) {
      // We are just starting, so read first chunk length.
      if (position + 2 >= blob.size) {
        error('blob is too short');
        return;
      }
      readBlobSlice(blob, position, position + 2, function(data) {
        nextChunkSize = (data[0] | data[1] << 8);
        position = 2;
        // Now that we have chunk size, call ourselves again.
        postNextChunk();
      });
    } else {
      // Read next chunk + length of the following chunk after it.
      var isLast = false;
      var end = position + nextChunkSize + 16 /* tag */ + 2 /* length */;
      if (end >= blob.size) {
        end = blob.size;
        isLast = true;
      }
      readBlobSlice(blob, position - 2 /* include chunk length */, end, function(chunk) {
        if (!isLast) {
          // Read next chunk's length.
          nextChunkSize = (chunk[chunk.length-2] | chunk[chunk.length-1] << 8);
          // Slice the length off.
          chunk = chunk.subarray(0, chunk.length-2);
        } else {
          nextChunkSize = 0;
        }
        // Decrypt.
        worker.postMessage({
          name: 'DECRYPT_CHUNK',
          chunk: chunk,
          isLast: isLast
        });
        // Advance position.
        position = end;
      });
    }
  }

  // Start decryption!
  worker.postMessage({
    name: 'DECRYPT_START',
    key: key,
    nonce: nonce
  });
}


// TRYING!

var key = new Uint8Array(32);
var nonce = new Uint8Array(16);
//var arr = nacl.util.decodeUTF8('Hello, chunky!');
var arr = new Uint8Array(10 * 1024*1024);
for (var i = 0; i < arr.length; i++) arr[i] = i & 0xff;
var blob = new Blob([arr]);

var startTime = new Date();

encryptBlob(
  key,
  nonce,
  blob,
  'application/x-encrypted-things',
  function(encryptedBlob) {
    console.log('encryption finished in ', (((new Date()) - startTime) / 1000) + ' s');
    console.log('encryptedBlob:', encryptedBlob);

    startTime = new Date();
    document.body.innerHTML = '<a href="' + URL.createObjectURL(encryptedBlob) + '">Get encrypted</a><br>';

    decryptBlob(
      key,
      nonce,
      encryptedBlob,
      'application/octet-binary',
      function(decryptedBlob) {
        console.log('decryption finished in ', (((new Date()) - startTime) / 1000) + ' s');
        console.log('decryptedBlob:', decryptedBlob);
        compareBlobs(blob, decryptedBlob);
        //console.log('DECRYPTED:',  nacl.util.encodeUTF8(decryptedBlob));
        document.body.innerHTML += '<a href="' + URL.createObjectURL(decryptedBlob) + '">Get decrypted</a>';
      },
      function(err) {
        console.log('DECRYPTION ERROR: ' + err);
      },
      function(position, size) {
        console.log('decrypting... ' + position + '/' + size);
      }
    );

  },
  function(err) {
    console.log('ENCRYPTION ERROR: ' + err);
  },
  function(position, size) {
    console.log('encrypting... ' + position + '/' + size);
  }
);

function compareBlobs(a, b) {
  var r1 = new FileReader();
  r1.onload = function() {
    var r2 = new FileReader();
    r2.onload = function() {
      if (r1.result !== r2.result) {
        console.error('blobs differ');
      } else {
        console.log('blobs are equal');
      }
    }
    r2.readAsBinaryString(b);
  }
  r1.readAsBinaryString(a);
}
