module.exports = function (CryptoJS) {
  (function (undefined) {
      /*global CryptoJS:true */

      'use strict';

      // Shortcuts
      var C = CryptoJS;
      var C_lib = C.lib;
      var BlockCipherMode = C_lib.BlockCipherMode;
      var C_mode = C.mode;

      /**
      * Counter mode.
      */
      /*var CTR =*/ C_mode.CTR = (function () {
          var CTR = BlockCipherMode.extend();

          CTR.Encryptor = CTR.Decryptor = CTR.extend({
              processBlock: function (words, offset) {
                  // Shortcuts
                  var cipher = this._cipher;
                  var blockSize = cipher.blockSize;
                  var iv = this._iv;
                  var counter = this._counter;

                  // Generate keystream
                  if (iv) {
                      counter = this._counter = iv.slice(0);

                      // Remove IV for subsequent blocks
                      this._iv = undefined;
                  }
                  var keystream = counter.slice(0);
                  cipher.encryptBlock(keystream, 0);

                  // Increment counter
                  counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0;

                  // Encrypt
                  for (var i = 0; i < blockSize; i++) {
                      words[offset + i] ^= keystream[i];
                  }
              }
          });

          return CTR;
      }());
  }());

}
