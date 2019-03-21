/*!
  otr.js v0.3.0-sualko - Thu Mar 21 2019
  (c) 2019 - Arlo Breault <arlolra@gmail.com>
  Freely distributed under the MPL-2.0 license.

  This file is concatenated for the browser.
  Please see: https://github.com/arlolra/otr
*/


(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(require('crypto')) :
    typeof define === 'function' && define.amd ? define(['crypto'], factory) :
    (global = global || self, factory(global.crypto));
}(this, function (crypto) { 'use strict';

    crypto = crypto && crypto.hasOwnProperty('default') ? crypto['default'] : crypto;

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    /**
     * CryptoJS core components.
     */

        /**
         * CryptoJS namespace.
         */
        var C = {};
        var CryptoJS = C;

        /**
         * Library namespace.
         */
        var C_lib = C.lib = {};

        /**
         * Base object for prototypal inheritance.
         */
        var Base = C_lib.Base = (function () {
            function F() {}

            return {
                /**
                 * Creates a new object that inherits from this object.
                 *
                 * @param {Object} overrides Properties to copy into the new object.
                 *
                 * @return {Object} The new object.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var MyType = CryptoJS.lib.Base.extend({
                 *         field: 'value',
                 *
                 *         method: function () {
                 *         }
                 *     });
                 */
                extend: function (overrides) {
                    // Spawn
                    F.prototype = this;
                    var subtype = new F();

                    // Augment
                    if (overrides) {
                        subtype.mixIn(overrides);
                    }

                    // Create default initializer
                    if (!subtype.hasOwnProperty('init')) {
                        subtype.init = function () {
                            subtype.$super.init.apply(this, arguments);
                        };
                    }

                    // Initializer's prototype is the subtype object
                    subtype.init.prototype = subtype;

                    // Reference supertype
                    subtype.$super = this;

                    return subtype;
                },

                /**
                 * Extends this object and runs the init method.
                 * Arguments to create() will be passed to init().
                 *
                 * @return {Object} The new object.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var instance = MyType.create();
                 */
                create: function () {
                    var instance = this.extend();
                    instance.init.apply(instance, arguments);

                    return instance;
                },

                /**
                 * Initializes a newly created object.
                 * Override this method to add some logic when your objects are created.
                 *
                 * @example
                 *
                 *     var MyType = CryptoJS.lib.Base.extend({
                 *         init: function () {
                 *             // ...
                 *         }
                 *     });
                 */
                init: function () {
                },

                /**
                 * Copies properties into this object.
                 *
                 * @param {Object} properties The properties to mix in.
                 *
                 * @example
                 *
                 *     MyType.mixIn({
                 *         field: 'value'
                 *     });
                 */
                mixIn: function (properties) {
                    for (var propertyName in properties) {
                        if (properties.hasOwnProperty(propertyName)) {
                            this[propertyName] = properties[propertyName];
                        }
                    }

                    // IE won't copy toString using the loop above
                    if (properties.hasOwnProperty('toString')) {
                        this.toString = properties.toString;
                    }
                },

                /**
                 * Creates a copy of this object.
                 *
                 * @return {Object} The clone.
                 *
                 * @example
                 *
                 *     var clone = instance.clone();
                 */
                clone: function () {
                    return this.init.prototype.extend(this);
                }
            };
        }());

        /**
         * An array of 32-bit words.
         *
         * @property {Array} words The array of 32-bit words.
         * @property {number} sigBytes The number of significant bytes in this word array.
         */
        var WordArray = C_lib.WordArray = Base.extend({
            /**
             * Initializes a newly created word array.
             *
             * @param {Array} words (Optional) An array of 32-bit words.
             * @param {number} sigBytes (Optional) The number of significant bytes in the words.
             *
             * @example
             *
             *     var wordArray = CryptoJS.lib.WordArray.create();
             *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
             *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
             */
            init: function (words, sigBytes) {
                words = this.words = words || [];

                if (sigBytes != undefined) {
                    this.sigBytes = sigBytes;
                } else {
                    this.sigBytes = words.length * 4;
                }
            },

            /**
             * Converts this word array to a string.
             *
             * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
             *
             * @return {string} The stringified word array.
             *
             * @example
             *
             *     var string = wordArray + '';
             *     var string = wordArray.toString();
             *     var string = wordArray.toString(CryptoJS.enc.Utf8);
             */
            toString: function (encoder) {
                return (encoder || Hex).stringify(this);
            },

            /**
             * Concatenates a word array to this word array.
             *
             * @param {WordArray} wordArray The word array to append.
             *
             * @return {WordArray} This word array.
             *
             * @example
             *
             *     wordArray1.concat(wordArray2);
             */
            concat: function (wordArray) {
                // Shortcuts
                var thisWords = this.words;
                var thatWords = wordArray.words;
                var thisSigBytes = this.sigBytes;
                var thatSigBytes = wordArray.sigBytes;

                // Clamp excess bits
                this.clamp();

                // Concat
                if (thisSigBytes % 4) {
                    // Copy one byte at a time
                    for (var i = 0; i < thatSigBytes; i++) {
                        var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                    }
                } else if (thatWords.length > 0xffff) {
                    // Copy one word at a time
                    for (var i = 0; i < thatSigBytes; i += 4) {
                        thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                    }
                } else {
                    // Copy all words at once
                    thisWords.push.apply(thisWords, thatWords);
                }
                this.sigBytes += thatSigBytes;

                // Chainable
                return this;
            },

            /**
             * Removes insignificant bits.
             *
             * @example
             *
             *     wordArray.clamp();
             */
            clamp: function () {
                // Shortcuts
                var words = this.words;
                var sigBytes = this.sigBytes;

                // Clamp
                words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
                words.length = Math.ceil(sigBytes / 4);
            },

            /**
             * Creates a copy of this word array.
             *
             * @return {WordArray} The clone.
             *
             * @example
             *
             *     var clone = wordArray.clone();
             */
            clone: function () {
                var clone = Base.clone.call(this);
                clone.words = this.words.slice(0);

                return clone;
            },

            /**
             * Creates a word array filled with random bytes.
             *
             * @param {number} nBytes The number of random bytes to generate.
             *
             * @return {WordArray} The random word array.
             *
             * @static
             *
             * @example
             *
             *     var wordArray = CryptoJS.lib.WordArray.random(16);
             */
            random: function (nBytes) {
                var words = [];
                for (var i = 0; i < nBytes; i += 4) {
                    words.push((Math.random() * 0x100000000) | 0);
                }

                return new WordArray.init(words, nBytes);
            }
        });

        /**
         * Encoder namespace.
         */
        var C_enc = C.enc = {};

        /**
         * Hex encoding strategy.
         */
        var Hex = C_enc.Hex = {
            /**
             * Converts a word array to a hex string.
             *
             * @param {WordArray} wordArray The word array.
             *
             * @return {string} The hex string.
             *
             * @static
             *
             * @example
             *
             *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
             */
            stringify: function (wordArray) {
                // Shortcuts
                var words = wordArray.words;
                var sigBytes = wordArray.sigBytes;

                // Convert
                var hexChars = [];
                for (var i = 0; i < sigBytes; i++) {
                    var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    hexChars.push((bite >>> 4).toString(16));
                    hexChars.push((bite & 0x0f).toString(16));
                }

                return hexChars.join('');
            },

            /**
             * Converts a hex string to a word array.
             *
             * @param {string} hexStr The hex string.
             *
             * @return {WordArray} The word array.
             *
             * @static
             *
             * @example
             *
             *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
             */
            parse: function (hexStr) {
                // Shortcut
                var hexStrLength = hexStr.length;

                // Convert
                var words = [];
                for (var i = 0; i < hexStrLength; i += 2) {
                    words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
                }

                return new WordArray.init(words, hexStrLength / 2);
            }
        };

        /**
         * Latin1 encoding strategy.
         */
        var Latin1 = C_enc.Latin1 = {
            /**
             * Converts a word array to a Latin1 string.
             *
             * @param {WordArray} wordArray The word array.
             *
             * @return {string} The Latin1 string.
             *
             * @static
             *
             * @example
             *
             *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
             */
            stringify: function (wordArray) {
                // Shortcuts
                var words = wordArray.words;
                var sigBytes = wordArray.sigBytes;

                // Convert
                var latin1Chars = [];
                for (var i = 0; i < sigBytes; i++) {
                    var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    latin1Chars.push(String.fromCharCode(bite));
                }

                return latin1Chars.join('');
            },

            /**
             * Converts a Latin1 string to a word array.
             *
             * @param {string} latin1Str The Latin1 string.
             *
             * @return {WordArray} The word array.
             *
             * @static
             *
             * @example
             *
             *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
             */
            parse: function (latin1Str) {
                // Shortcut
                var latin1StrLength = latin1Str.length;

                // Convert
                var words = [];
                for (var i = 0; i < latin1StrLength; i++) {
                    words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
                }

                return new WordArray.init(words, latin1StrLength);
            }
        };

        /**
         * UTF-8 encoding strategy.
         */
        var Utf8 = C_enc.Utf8 = {
            /**
             * Converts a word array to a UTF-8 string.
             *
             * @param {WordArray} wordArray The word array.
             *
             * @return {string} The UTF-8 string.
             *
             * @static
             *
             * @example
             *
             *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
             */
            stringify: function (wordArray) {
                try {
                    return decodeURIComponent(escape(Latin1.stringify(wordArray)));
                } catch (e) {
                    throw new Error('Malformed UTF-8 data');
                }
            },

            /**
             * Converts a UTF-8 string to a word array.
             *
             * @param {string} utf8Str The UTF-8 string.
             *
             * @return {WordArray} The word array.
             *
             * @static
             *
             * @example
             *
             *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
             */
            parse: function (utf8Str) {
                return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
            }
        };

        /**
         * Abstract buffered block algorithm template.
         *
         * The property blockSize must be implemented in a concrete subtype.
         *
         * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
         */
        var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
            /**
             * Resets this block algorithm's data buffer to its initial state.
             *
             * @example
             *
             *     bufferedBlockAlgorithm.reset();
             */
            reset: function () {
                // Initial values
                this._data = new WordArray.init();
                this._nDataBytes = 0;
            },

            /**
             * Adds new data to this block algorithm's buffer.
             *
             * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
             *
             * @example
             *
             *     bufferedBlockAlgorithm._append('data');
             *     bufferedBlockAlgorithm._append(wordArray);
             */
            _append: function (data) {
                // Convert string to WordArray, else assume WordArray already
                if (typeof data == 'string') {
                    data = Utf8.parse(data);
                }

                // Append
                this._data.concat(data);
                this._nDataBytes += data.sigBytes;
            },

            /**
             * Processes available data blocks.
             *
             * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
             *
             * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
             *
             * @return {WordArray} The processed data.
             *
             * @example
             *
             *     var processedData = bufferedBlockAlgorithm._process();
             *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
             */
            _process: function (doFlush) {
                // Shortcuts
                var data = this._data;
                var dataWords = data.words;
                var dataSigBytes = data.sigBytes;
                var blockSize = this.blockSize;
                var blockSizeBytes = blockSize * 4;

                // Count blocks ready
                var nBlocksReady = dataSigBytes / blockSizeBytes;
                if (doFlush) {
                    // Round up to include partial blocks
                    nBlocksReady = Math.ceil(nBlocksReady);
                } else {
                    // Round down to include only full blocks,
                    // less the number of blocks that must remain in the buffer
                    nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
                }

                // Count words ready
                var nWordsReady = nBlocksReady * blockSize;

                // Count bytes ready
                var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

                // Process blocks
                if (nWordsReady) {
                    for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                        // Perform concrete-algorithm logic
                        this._doProcessBlock(dataWords, offset);
                    }

                    // Remove processed words
                    var processedWords = dataWords.splice(0, nWordsReady);
                    data.sigBytes -= nBytesReady;
                }

                // Return processed words
                return new WordArray.init(processedWords, nBytesReady);
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             *
             * @example
             *
             *     var clone = bufferedBlockAlgorithm.clone();
             */
            clone: function () {
                var clone = Base.clone.call(this);
                clone._data = this._data.clone();

                return clone;
            },

            _minBufferSize: 0
        });

        /**
         * Abstract hasher template.
         *
         * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
         */
        var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
            /**
             * Configuration options.
             */
            cfg: Base.extend(),

            /**
             * Initializes a newly created hasher.
             *
             * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
             *
             * @example
             *
             *     var hasher = CryptoJS.algo.SHA256.create();
             */
            init: function (cfg) {
                // Apply config defaults
                this.cfg = this.cfg.extend(cfg);

                // Set initial values
                this.reset();
            },

            /**
             * Resets this hasher to its initial state.
             *
             * @example
             *
             *     hasher.reset();
             */
            reset: function () {
                // Reset data buffer
                BufferedBlockAlgorithm.reset.call(this);

                // Perform concrete-hasher logic
                this._doReset();
            },

            /**
             * Updates this hasher with a message.
             *
             * @param {WordArray|string} messageUpdate The message to append.
             *
             * @return {Hasher} This hasher.
             *
             * @example
             *
             *     hasher.update('message');
             *     hasher.update(wordArray);
             */
            update: function (messageUpdate) {
                // Append
                this._append(messageUpdate);

                // Update the hash
                this._process();

                // Chainable
                return this;
            },

            /**
             * Finalizes the hash computation.
             * Note that the finalize operation is effectively a destructive, read-once operation.
             *
             * @param {WordArray|string} messageUpdate (Optional) A final message update.
             *
             * @return {WordArray} The hash.
             *
             * @example
             *
             *     var hash = hasher.finalize();
             *     var hash = hasher.finalize('message');
             *     var hash = hasher.finalize(wordArray);
             */
            finalize: function (messageUpdate) {
                // Final message update
                if (messageUpdate) {
                    this._append(messageUpdate);
                }

                // Perform concrete-hasher logic
                var hash = this._doFinalize();

                return hash;
            },

            blockSize: 512/32,

            /**
             * Creates a shortcut function to a hasher's object interface.
             *
             * @param {Hasher} hasher The hasher to create a helper for.
             *
             * @return {Function} The shortcut function.
             *
             * @static
             *
             * @example
             *
             *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
             */
            _createHelper: function (hasher) {
                return function (message, cfg) {
                    return new hasher.init(cfg).finalize(message);
                };
            },

            /**
             * Creates a shortcut function to the HMAC's object interface.
             *
             * @param {Hasher} hasher The hasher to use in this HMAC helper.
             *
             * @return {Function} The shortcut function.
             *
             * @static
             *
             * @example
             *
             *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
             */
            _createHmacHelper: function (hasher) {
                return function (message, key) {
                    return new C_algo.HMAC.init(hasher, key).finalize(message);
                };
            }
        });

        /**
         * Algorithm namespace.
         */
        var C_algo = C.algo = {};

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    (function () {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var WordArray = C_lib.WordArray;
        var C_enc = C.enc;

        /**
         * Base64 encoding strategy.
         */
        var Base64 = C_enc.Base64 = {
            /**
             * Converts a word array to a Base64 string.
             *
             * @param {WordArray} wordArray The word array.
             *
             * @return {string} The Base64 string.
             *
             * @static
             *
             * @example
             *
             *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
             */
            stringify: function (wordArray) {
                // Shortcuts
                var words = wordArray.words;
                var sigBytes = wordArray.sigBytes;
                var map = this._map;

                // Clamp excess bits
                wordArray.clamp();

                // Convert
                var base64Chars = [];
                for (var i = 0; i < sigBytes; i += 3) {
                    var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
                    var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
                    var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

                    var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

                    for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
                        base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
                    }
                }

                // Add padding
                var paddingChar = map.charAt(64);
                if (paddingChar) {
                    while (base64Chars.length % 4) {
                        base64Chars.push(paddingChar);
                    }
                }

                return base64Chars.join('');
            },

            /**
             * Converts a Base64 string to a word array.
             *
             * @param {string} base64Str The Base64 string.
             *
             * @return {WordArray} The word array.
             *
             * @static
             *
             * @example
             *
             *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
             */
            parse: function (base64Str) {
                // Shortcuts
                var base64StrLength = base64Str.length;
                var map = this._map;

                // Ignore padding
                var paddingChar = map.charAt(64);
                if (paddingChar) {
                    var paddingIndex = base64Str.indexOf(paddingChar);
                    if (paddingIndex != -1) {
                        base64StrLength = paddingIndex;
                    }
                }

                // Convert
                var words = [];
                var nBytes = 0;
                for (var i = 0; i < base64StrLength; i++) {
                    if (i % 4) {
                        var bits1 = map.indexOf(base64Str.charAt(i - 1)) << ((i % 4) * 2);
                        var bits2 = map.indexOf(base64Str.charAt(i)) >>> (6 - (i % 4) * 2);
                        words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
                        nBytes++;
                    }
                }

                return WordArray.create(words, nBytes);
            },

            _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        };
    }());

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    /**
     * Cipher core components.
     */
    CryptoJS.lib.Cipher || (function (undefined$1) {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var Base = C_lib.Base;
        var WordArray = C_lib.WordArray;
        var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
        var C_enc = C.enc;
        var Utf8 = C_enc.Utf8;
        var Base64 = C_enc.Base64;
        var C_algo = C.algo;
        var EvpKDF = C_algo.EvpKDF;

        /**
         * Abstract base cipher template.
         *
         * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
         * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
         * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
         * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
         */
        var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
            /**
             * Configuration options.
             *
             * @property {WordArray} iv The IV to use for this operation.
             */
            cfg: Base.extend(),

            /**
             * Creates this cipher in encryption mode.
             *
             * @param {WordArray} key The key.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @return {Cipher} A cipher instance.
             *
             * @static
             *
             * @example
             *
             *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
             */
            createEncryptor: function (key, cfg) {
                return this.create(this._ENC_XFORM_MODE, key, cfg);
            },

            /**
             * Creates this cipher in decryption mode.
             *
             * @param {WordArray} key The key.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @return {Cipher} A cipher instance.
             *
             * @static
             *
             * @example
             *
             *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
             */
            createDecryptor: function (key, cfg) {
                return this.create(this._DEC_XFORM_MODE, key, cfg);
            },

            /**
             * Initializes a newly created cipher.
             *
             * @param {number} xformMode Either the encryption or decryption transormation mode constant.
             * @param {WordArray} key The key.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @example
             *
             *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
             */
            init: function (xformMode, key, cfg) {
                // Apply config defaults
                this.cfg = this.cfg.extend(cfg);

                // Store transform mode and key
                this._xformMode = xformMode;
                this._key = key;

                // Set initial values
                this.reset();
            },

            /**
             * Resets this cipher to its initial state.
             *
             * @example
             *
             *     cipher.reset();
             */
            reset: function () {
                // Reset data buffer
                BufferedBlockAlgorithm.reset.call(this);

                // Perform concrete-cipher logic
                this._doReset();
            },

            /**
             * Adds data to be encrypted or decrypted.
             *
             * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
             *
             * @return {WordArray} The data after processing.
             *
             * @example
             *
             *     var encrypted = cipher.process('data');
             *     var encrypted = cipher.process(wordArray);
             */
            process: function (dataUpdate) {
                // Append
                this._append(dataUpdate);

                // Process available blocks
                return this._process();
            },

            /**
             * Finalizes the encryption or decryption process.
             * Note that the finalize operation is effectively a destructive, read-once operation.
             *
             * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
             *
             * @return {WordArray} The data after final processing.
             *
             * @example
             *
             *     var encrypted = cipher.finalize();
             *     var encrypted = cipher.finalize('data');
             *     var encrypted = cipher.finalize(wordArray);
             */
            finalize: function (dataUpdate) {
                // Final data update
                if (dataUpdate) {
                    this._append(dataUpdate);
                }

                // Perform concrete-cipher logic
                var finalProcessedData = this._doFinalize();

                return finalProcessedData;
            },

            keySize: 128/32,

            ivSize: 128/32,

            _ENC_XFORM_MODE: 1,

            _DEC_XFORM_MODE: 2,

            /**
             * Creates shortcut functions to a cipher's object interface.
             *
             * @param {Cipher} cipher The cipher to create a helper for.
             *
             * @return {Object} An object with encrypt and decrypt shortcut functions.
             *
             * @static
             *
             * @example
             *
             *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
             */
            _createHelper: (function () {
                function selectCipherStrategy(key) {
                    if (typeof key == 'string') {
                        return PasswordBasedCipher;
                    } else {
                        return SerializableCipher;
                    }
                }

                return function (cipher) {
                    return {
                        encrypt: function (message, key, cfg) {
                            return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
                        },

                        decrypt: function (ciphertext, key, cfg) {
                            return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
                        }
                    };
                };
            }())
        });

        /**
         * Abstract base stream cipher template.
         *
         * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
         */
        var StreamCipher = C_lib.StreamCipher = Cipher.extend({
            _doFinalize: function () {
                // Process partial blocks
                var finalProcessedBlocks = this._process(!!'flush');

                return finalProcessedBlocks;
            },

            blockSize: 1
        });

        /**
         * Mode namespace.
         */
        var C_mode = C.mode = {};

        /**
         * Abstract base block cipher mode template.
         */
        var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
            /**
             * Creates this mode for encryption.
             *
             * @param {Cipher} cipher A block cipher instance.
             * @param {Array} iv The IV words.
             *
             * @static
             *
             * @example
             *
             *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
             */
            createEncryptor: function (cipher, iv) {
                return this.Encryptor.create(cipher, iv);
            },

            /**
             * Creates this mode for decryption.
             *
             * @param {Cipher} cipher A block cipher instance.
             * @param {Array} iv The IV words.
             *
             * @static
             *
             * @example
             *
             *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
             */
            createDecryptor: function (cipher, iv) {
                return this.Decryptor.create(cipher, iv);
            },

            /**
             * Initializes a newly created mode.
             *
             * @param {Cipher} cipher A block cipher instance.
             * @param {Array} iv The IV words.
             *
             * @example
             *
             *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
             */
            init: function (cipher, iv) {
                this._cipher = cipher;
                this._iv = iv;
            }
        });

        /**
         * Cipher Block Chaining mode.
         */
        var CBC = C_mode.CBC = (function () {
            /**
             * Abstract base CBC mode.
             */
            var CBC = BlockCipherMode.extend();

            /**
             * CBC encryptor.
             */
            CBC.Encryptor = CBC.extend({
                /**
                 * Processes the data block at offset.
                 *
                 * @param {Array} words The data words to operate on.
                 * @param {number} offset The offset where the block starts.
                 *
                 * @example
                 *
                 *     mode.processBlock(data.words, offset);
                 */
                processBlock: function (words, offset) {
                    // Shortcuts
                    var cipher = this._cipher;
                    var blockSize = cipher.blockSize;

                    // XOR and encrypt
                    xorBlock.call(this, words, offset, blockSize);
                    cipher.encryptBlock(words, offset);

                    // Remember this block to use with next block
                    this._prevBlock = words.slice(offset, offset + blockSize);
                }
            });

            /**
             * CBC decryptor.
             */
            CBC.Decryptor = CBC.extend({
                /**
                 * Processes the data block at offset.
                 *
                 * @param {Array} words The data words to operate on.
                 * @param {number} offset The offset where the block starts.
                 *
                 * @example
                 *
                 *     mode.processBlock(data.words, offset);
                 */
                processBlock: function (words, offset) {
                    // Shortcuts
                    var cipher = this._cipher;
                    var blockSize = cipher.blockSize;

                    // Remember this block to use with next block
                    var thisBlock = words.slice(offset, offset + blockSize);

                    // Decrypt and XOR
                    cipher.decryptBlock(words, offset);
                    xorBlock.call(this, words, offset, blockSize);

                    // This block becomes the previous block
                    this._prevBlock = thisBlock;
                }
            });

            function xorBlock(words, offset, blockSize) {
                // Shortcut
                var iv = this._iv;

                // Choose mixing block
                if (iv) {
                    var block = iv;

                    // Remove IV for subsequent blocks
                    this._iv = undefined$1;
                } else {
                    var block = this._prevBlock;
                }

                // XOR blocks
                for (var i = 0; i < blockSize; i++) {
                    words[offset + i] ^= block[i];
                }
            }

            return CBC;
        }());

        /**
         * Padding namespace.
         */
        var C_pad = C.pad = {};

        /**
         * PKCS #5/7 padding strategy.
         */
        var Pkcs7 = C_pad.Pkcs7 = {
            /**
             * Pads data using the algorithm defined in PKCS #5/7.
             *
             * @param {WordArray} data The data to pad.
             * @param {number} blockSize The multiple that the data should be padded to.
             *
             * @static
             *
             * @example
             *
             *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
             */
            pad: function (data, blockSize) {
                // Shortcut
                var blockSizeBytes = blockSize * 4;

                // Count padding bytes
                var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

                // Create padding word
                var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

                // Create padding
                var paddingWords = [];
                for (var i = 0; i < nPaddingBytes; i += 4) {
                    paddingWords.push(paddingWord);
                }
                var padding = WordArray.create(paddingWords, nPaddingBytes);

                // Add padding
                data.concat(padding);
            },

            /**
             * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
             *
             * @param {WordArray} data The data to unpad.
             *
             * @static
             *
             * @example
             *
             *     CryptoJS.pad.Pkcs7.unpad(wordArray);
             */
            unpad: function (data) {
                // Get number of padding bytes from last byte
                var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

                // Remove padding
                data.sigBytes -= nPaddingBytes;
            }
        };

        /**
         * Abstract base block cipher template.
         *
         * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
         */
        var BlockCipher = C_lib.BlockCipher = Cipher.extend({
            /**
             * Configuration options.
             *
             * @property {Mode} mode The block mode to use. Default: CBC
             * @property {Padding} padding The padding strategy to use. Default: Pkcs7
             */
            cfg: Cipher.cfg.extend({
                mode: CBC,
                padding: Pkcs7
            }),

            reset: function () {
                // Reset cipher
                Cipher.reset.call(this);

                // Shortcuts
                var cfg = this.cfg;
                var iv = cfg.iv;
                var mode = cfg.mode;

                // Reset block mode
                if (this._xformMode == this._ENC_XFORM_MODE) {
                    var modeCreator = mode.createEncryptor;
                } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
                    var modeCreator = mode.createDecryptor;

                    // Keep at least one block in the buffer for unpadding
                    this._minBufferSize = 1;
                }
                this._mode = modeCreator.call(mode, this, iv && iv.words);
            },

            _doProcessBlock: function (words, offset) {
                this._mode.processBlock(words, offset);
            },

            _doFinalize: function () {
                // Shortcut
                var padding = this.cfg.padding;

                // Finalize
                if (this._xformMode == this._ENC_XFORM_MODE) {
                    // Pad data
                    padding.pad(this._data, this.blockSize);

                    // Process final blocks
                    var finalProcessedBlocks = this._process(!!'flush');
                } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
                    // Process final blocks
                    var finalProcessedBlocks = this._process(!!'flush');

                    // Unpad data
                    padding.unpad(finalProcessedBlocks);
                }

                return finalProcessedBlocks;
            },

            blockSize: 128/32
        });

        /**
         * A collection of cipher parameters.
         *
         * @property {WordArray} ciphertext The raw ciphertext.
         * @property {WordArray} key The key to this ciphertext.
         * @property {WordArray} iv The IV used in the ciphering operation.
         * @property {WordArray} salt The salt used with a key derivation function.
         * @property {Cipher} algorithm The cipher algorithm.
         * @property {Mode} mode The block mode used in the ciphering operation.
         * @property {Padding} padding The padding scheme used in the ciphering operation.
         * @property {number} blockSize The block size of the cipher.
         * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
         */
        var CipherParams = C_lib.CipherParams = Base.extend({
            /**
             * Initializes a newly created cipher params object.
             *
             * @param {Object} cipherParams An object with any of the possible cipher parameters.
             *
             * @example
             *
             *     var cipherParams = CryptoJS.lib.CipherParams.create({
             *         ciphertext: ciphertextWordArray,
             *         key: keyWordArray,
             *         iv: ivWordArray,
             *         salt: saltWordArray,
             *         algorithm: CryptoJS.algo.AES,
             *         mode: CryptoJS.mode.CBC,
             *         padding: CryptoJS.pad.PKCS7,
             *         blockSize: 4,
             *         formatter: CryptoJS.format.OpenSSL
             *     });
             */
            init: function (cipherParams) {
                this.mixIn(cipherParams);
            },

            /**
             * Converts this cipher params object to a string.
             *
             * @param {Format} formatter (Optional) The formatting strategy to use.
             *
             * @return {string} The stringified cipher params.
             *
             * @throws Error If neither the formatter nor the default formatter is set.
             *
             * @example
             *
             *     var string = cipherParams + '';
             *     var string = cipherParams.toString();
             *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
             */
            toString: function (formatter) {
                return (formatter || this.formatter).stringify(this);
            }
        });

        /**
         * Format namespace.
         */
        var C_format = C.format = {};

        /**
         * OpenSSL formatting strategy.
         */
        var OpenSSLFormatter = C_format.OpenSSL = {
            /**
             * Converts a cipher params object to an OpenSSL-compatible string.
             *
             * @param {CipherParams} cipherParams The cipher params object.
             *
             * @return {string} The OpenSSL-compatible string.
             *
             * @static
             *
             * @example
             *
             *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
             */
            stringify: function (cipherParams) {
                // Shortcuts
                var ciphertext = cipherParams.ciphertext;
                var salt = cipherParams.salt;

                // Format
                if (salt) {
                    var wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
                } else {
                    var wordArray = ciphertext;
                }

                return wordArray.toString(Base64);
            },

            /**
             * Converts an OpenSSL-compatible string to a cipher params object.
             *
             * @param {string} openSSLStr The OpenSSL-compatible string.
             *
             * @return {CipherParams} The cipher params object.
             *
             * @static
             *
             * @example
             *
             *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
             */
            parse: function (openSSLStr) {
                // Parse base64
                var ciphertext = Base64.parse(openSSLStr);

                // Shortcut
                var ciphertextWords = ciphertext.words;

                // Test for salt
                if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
                    // Extract salt
                    var salt = WordArray.create(ciphertextWords.slice(2, 4));

                    // Remove salt from ciphertext
                    ciphertextWords.splice(0, 4);
                    ciphertext.sigBytes -= 16;
                }

                return CipherParams.create({ ciphertext: ciphertext, salt: salt });
            }
        };

        /**
         * A cipher wrapper that returns ciphertext as a serializable cipher params object.
         */
        var SerializableCipher = C_lib.SerializableCipher = Base.extend({
            /**
             * Configuration options.
             *
             * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
             */
            cfg: Base.extend({
                format: OpenSSLFormatter
            }),

            /**
             * Encrypts a message.
             *
             * @param {Cipher} cipher The cipher algorithm to use.
             * @param {WordArray|string} message The message to encrypt.
             * @param {WordArray} key The key.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @return {CipherParams} A cipher params object.
             *
             * @static
             *
             * @example
             *
             *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
             *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
             *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
             */
            encrypt: function (cipher, message, key, cfg) {
                // Apply config defaults
                cfg = this.cfg.extend(cfg);

                // Encrypt
                var encryptor = cipher.createEncryptor(key, cfg);
                var ciphertext = encryptor.finalize(message);

                // Shortcut
                var cipherCfg = encryptor.cfg;

                // Create and return serializable cipher params
                return CipherParams.create({
                    ciphertext: ciphertext,
                    key: key,
                    iv: cipherCfg.iv,
                    algorithm: cipher,
                    mode: cipherCfg.mode,
                    padding: cipherCfg.padding,
                    blockSize: cipher.blockSize,
                    formatter: cfg.format
                });
            },

            /**
             * Decrypts serialized ciphertext.
             *
             * @param {Cipher} cipher The cipher algorithm to use.
             * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
             * @param {WordArray} key The key.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @return {WordArray} The plaintext.
             *
             * @static
             *
             * @example
             *
             *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
             *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
             */
            decrypt: function (cipher, ciphertext, key, cfg) {
                // Apply config defaults
                cfg = this.cfg.extend(cfg);

                // Convert string to CipherParams
                ciphertext = this._parse(ciphertext, cfg.format);

                // Decrypt
                var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

                return plaintext;
            },

            /**
             * Converts serialized ciphertext to CipherParams,
             * else assumed CipherParams already and returns ciphertext unchanged.
             *
             * @param {CipherParams|string} ciphertext The ciphertext.
             * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
             *
             * @return {CipherParams} The unserialized ciphertext.
             *
             * @static
             *
             * @example
             *
             *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
             */
            _parse: function (ciphertext, format) {
                if (typeof ciphertext == 'string') {
                    return format.parse(ciphertext, this);
                } else {
                    return ciphertext;
                }
            }
        });

        /**
         * Key derivation function namespace.
         */
        var C_kdf = C.kdf = {};

        /**
         * OpenSSL key derivation function.
         */
        var OpenSSLKdf = C_kdf.OpenSSL = {
            /**
             * Derives a key and IV from a password.
             *
             * @param {string} password The password to derive from.
             * @param {number} keySize The size in words of the key to generate.
             * @param {number} ivSize The size in words of the IV to generate.
             * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
             *
             * @return {CipherParams} A cipher params object with the key, IV, and salt.
             *
             * @static
             *
             * @example
             *
             *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
             *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
             */
            execute: function (password, keySize, ivSize, salt) {
                // Generate random salt
                if (!salt) {
                    salt = WordArray.random(64/8);
                }

                // Derive key and IV
                var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

                // Separate key and IV
                var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
                key.sigBytes = keySize * 4;

                // Return params
                return CipherParams.create({ key: key, iv: iv, salt: salt });
            }
        };

        /**
         * A serializable cipher wrapper that derives the key from a password,
         * and returns ciphertext as a serializable cipher params object.
         */
        var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
            /**
             * Configuration options.
             *
             * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
             */
            cfg: SerializableCipher.cfg.extend({
                kdf: OpenSSLKdf
            }),

            /**
             * Encrypts a message using a password.
             *
             * @param {Cipher} cipher The cipher algorithm to use.
             * @param {WordArray|string} message The message to encrypt.
             * @param {string} password The password.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @return {CipherParams} A cipher params object.
             *
             * @static
             *
             * @example
             *
             *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
             *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
             */
            encrypt: function (cipher, message, password, cfg) {
                // Apply config defaults
                cfg = this.cfg.extend(cfg);

                // Derive key and other params
                var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

                // Add IV to config
                cfg.iv = derivedParams.iv;

                // Encrypt
                var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

                // Mix in derived params
                ciphertext.mixIn(derivedParams);

                return ciphertext;
            },

            /**
             * Decrypts serialized ciphertext using a password.
             *
             * @param {Cipher} cipher The cipher algorithm to use.
             * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
             * @param {string} password The password.
             * @param {Object} cfg (Optional) The configuration options to use for this operation.
             *
             * @return {WordArray} The plaintext.
             *
             * @static
             *
             * @example
             *
             *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
             *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
             */
            decrypt: function (cipher, ciphertext, password, cfg) {
                // Apply config defaults
                cfg = this.cfg.extend(cfg);

                // Convert string to CipherParams
                ciphertext = this._parse(ciphertext, cfg.format);

                // Derive key and other params
                var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

                // Add IV to config
                cfg.iv = derivedParams.iv;

                // Decrypt
                var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

                return plaintext;
            }
        });
    }());

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    (function () {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var BlockCipher = C_lib.BlockCipher;
        var C_algo = C.algo;

        // Lookup tables
        var SBOX = [];
        var INV_SBOX = [];
        var SUB_MIX_0 = [];
        var SUB_MIX_1 = [];
        var SUB_MIX_2 = [];
        var SUB_MIX_3 = [];
        var INV_SUB_MIX_0 = [];
        var INV_SUB_MIX_1 = [];
        var INV_SUB_MIX_2 = [];
        var INV_SUB_MIX_3 = [];

        // Compute lookup tables
        (function () {
            // Compute double table
            var d = [];
            for (var i = 0; i < 256; i++) {
                if (i < 128) {
                    d[i] = i << 1;
                } else {
                    d[i] = (i << 1) ^ 0x11b;
                }
            }

            // Walk GF(2^8)
            var x = 0;
            var xi = 0;
            for (var i = 0; i < 256; i++) {
                // Compute sbox
                var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
                sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
                SBOX[x] = sx;
                INV_SBOX[sx] = x;

                // Compute multiplication
                var x2 = d[x];
                var x4 = d[x2];
                var x8 = d[x4];

                // Compute sub bytes, mix columns tables
                var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
                SUB_MIX_0[x] = (t << 24) | (t >>> 8);
                SUB_MIX_1[x] = (t << 16) | (t >>> 16);
                SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
                SUB_MIX_3[x] = t;

                // Compute inv sub bytes, inv mix columns tables
                var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
                INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
                INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
                INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
                INV_SUB_MIX_3[sx] = t;

                // Compute next counter
                if (!x) {
                    x = xi = 1;
                } else {
                    x = x2 ^ d[d[d[x8 ^ x2]]];
                    xi ^= d[d[xi]];
                }
            }
        }());

        // Precomputed Rcon lookup
        var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

        /**
         * AES block cipher algorithm.
         */
        var AES = C_algo.AES = BlockCipher.extend({
            _doReset: function () {
                // Shortcuts
                var key = this._key;
                var keyWords = key.words;
                var keySize = key.sigBytes / 4;

                // Compute number of rounds
                var nRounds = this._nRounds = keySize + 6;

                // Compute number of key schedule rows
                var ksRows = (nRounds + 1) * 4;

                // Compute key schedule
                var keySchedule = this._keySchedule = [];
                for (var ksRow = 0; ksRow < ksRows; ksRow++) {
                    if (ksRow < keySize) {
                        keySchedule[ksRow] = keyWords[ksRow];
                    } else {
                        var t = keySchedule[ksRow - 1];

                        if (!(ksRow % keySize)) {
                            // Rot word
                            t = (t << 8) | (t >>> 24);

                            // Sub word
                            t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

                            // Mix Rcon
                            t ^= RCON[(ksRow / keySize) | 0] << 24;
                        } else if (keySize > 6 && ksRow % keySize == 4) {
                            // Sub word
                            t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
                        }

                        keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
                    }
                }

                // Compute inv key schedule
                var invKeySchedule = this._invKeySchedule = [];
                for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
                    var ksRow = ksRows - invKsRow;

                    if (invKsRow % 4) {
                        var t = keySchedule[ksRow];
                    } else {
                        var t = keySchedule[ksRow - 4];
                    }

                    if (invKsRow < 4 || ksRow <= 4) {
                        invKeySchedule[invKsRow] = t;
                    } else {
                        invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
                                                   INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
                    }
                }
            },

            encryptBlock: function (M, offset) {
                this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
            },

            decryptBlock: function (M, offset) {
                // Swap 2nd and 4th rows
                var t = M[offset + 1];
                M[offset + 1] = M[offset + 3];
                M[offset + 3] = t;

                this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

                // Inv swap 2nd and 4th rows
                var t = M[offset + 1];
                M[offset + 1] = M[offset + 3];
                M[offset + 3] = t;
            },

            _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
                // Shortcut
                var nRounds = this._nRounds;

                // Get input, add round key
                var s0 = M[offset]     ^ keySchedule[0];
                var s1 = M[offset + 1] ^ keySchedule[1];
                var s2 = M[offset + 2] ^ keySchedule[2];
                var s3 = M[offset + 3] ^ keySchedule[3];

                // Key schedule row counter
                var ksRow = 4;

                // Rounds
                for (var round = 1; round < nRounds; round++) {
                    // Shift rows, sub bytes, mix columns, add round key
                    var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
                    var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
                    var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
                    var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

                    // Update state
                    s0 = t0;
                    s1 = t1;
                    s2 = t2;
                    s3 = t3;
                }

                // Shift rows, sub bytes, add round key
                var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
                var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
                var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
                var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

                // Set output
                M[offset]     = t0;
                M[offset + 1] = t1;
                M[offset + 2] = t2;
                M[offset + 3] = t3;
            },

            keySize: 256/32
        });

        /**
         * Shortcut functions to the cipher's object interface.
         *
         * @example
         *
         *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
         *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
         */
        C.AES = BlockCipher._createHelper(AES);
    }());

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    (function () {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var WordArray = C_lib.WordArray;
        var Hasher = C_lib.Hasher;
        var C_algo = C.algo;

        // Reusable object
        var W = [];

        /**
         * SHA-1 hash algorithm.
         */
        var SHA1 = C_algo.SHA1 = Hasher.extend({
            _doReset: function () {
                this._hash = new WordArray.init([
                    0x67452301, 0xefcdab89,
                    0x98badcfe, 0x10325476,
                    0xc3d2e1f0
                ]);
            },

            _doProcessBlock: function (M, offset) {
                // Shortcut
                var H = this._hash.words;

                // Working variables
                var a = H[0];
                var b = H[1];
                var c = H[2];
                var d = H[3];
                var e = H[4];

                // Computation
                for (var i = 0; i < 80; i++) {
                    if (i < 16) {
                        W[i] = M[offset + i] | 0;
                    } else {
                        var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
                        W[i] = (n << 1) | (n >>> 31);
                    }

                    var t = ((a << 5) | (a >>> 27)) + e + W[i];
                    if (i < 20) {
                        t += ((b & c) | (~b & d)) + 0x5a827999;
                    } else if (i < 40) {
                        t += (b ^ c ^ d) + 0x6ed9eba1;
                    } else if (i < 60) {
                        t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
                    } else /* if (i < 80) */ {
                        t += (b ^ c ^ d) - 0x359d3e2a;
                    }

                    e = d;
                    d = c;
                    c = (b << 30) | (b >>> 2);
                    b = a;
                    a = t;
                }

                // Intermediate hash value
                H[0] = (H[0] + a) | 0;
                H[1] = (H[1] + b) | 0;
                H[2] = (H[2] + c) | 0;
                H[3] = (H[3] + d) | 0;
                H[4] = (H[4] + e) | 0;
            },

            _doFinalize: function () {
                // Shortcuts
                var data = this._data;
                var dataWords = data.words;

                var nBitsTotal = this._nDataBytes * 8;
                var nBitsLeft = data.sigBytes * 8;

                // Add padding
                dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
                dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
                dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
                data.sigBytes = dataWords.length * 4;

                // Hash final blocks
                this._process();

                // Return final computed hash
                return this._hash;
            },

            clone: function () {
                var clone = Hasher.clone.call(this);
                clone._hash = this._hash.clone();

                return clone;
            }
        });

        /**
         * Shortcut function to the hasher's object interface.
         *
         * @param {WordArray|string} message The message to hash.
         *
         * @return {WordArray} The hash.
         *
         * @static
         *
         * @example
         *
         *     var hash = CryptoJS.SHA1('message');
         *     var hash = CryptoJS.SHA1(wordArray);
         */
        C.SHA1 = Hasher._createHelper(SHA1);

        /**
         * Shortcut function to the HMAC's object interface.
         *
         * @param {WordArray|string} message The message to hash.
         * @param {WordArray|string} key The secret key.
         *
         * @return {WordArray} The HMAC.
         *
         * @static
         *
         * @example
         *
         *     var hmac = CryptoJS.HmacSHA1(message, key);
         */
        C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
    }());

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    (function (Math) {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var WordArray = C_lib.WordArray;
        var Hasher = C_lib.Hasher;
        var C_algo = C.algo;

        // Initialization and round constants tables
        var H = [];
        var K = [];

        // Compute constants
        (function () {
            function isPrime(n) {
                var sqrtN = Math.sqrt(n);
                for (var factor = 2; factor <= sqrtN; factor++) {
                    if (!(n % factor)) {
                        return false;
                    }
                }

                return true;
            }

            function getFractionalBits(n) {
                return ((n - (n | 0)) * 0x100000000) | 0;
            }

            var n = 2;
            var nPrime = 0;
            while (nPrime < 64) {
                if (isPrime(n)) {
                    if (nPrime < 8) {
                        H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
                    }
                    K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

                    nPrime++;
                }

                n++;
            }
        }());

        // Reusable object
        var W = [];

        /**
         * SHA-256 hash algorithm.
         */
        var SHA256 = C_algo.SHA256 = Hasher.extend({
            _doReset: function () {
                this._hash = new WordArray.init(H.slice(0));
            },

            _doProcessBlock: function (M, offset) {
                // Shortcut
                var H = this._hash.words;

                // Working variables
                var a = H[0];
                var b = H[1];
                var c = H[2];
                var d = H[3];
                var e = H[4];
                var f = H[5];
                var g = H[6];
                var h = H[7];

                // Computation
                for (var i = 0; i < 64; i++) {
                    if (i < 16) {
                        W[i] = M[offset + i] | 0;
                    } else {
                        var gamma0x = W[i - 15];
                        var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
                                      ((gamma0x << 14) | (gamma0x >>> 18)) ^
                                       (gamma0x >>> 3);

                        var gamma1x = W[i - 2];
                        var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                                      ((gamma1x << 13) | (gamma1x >>> 19)) ^
                                       (gamma1x >>> 10);

                        W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
                    }

                    var ch  = (e & f) ^ (~e & g);
                    var maj = (a & b) ^ (a & c) ^ (b & c);

                    var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
                    var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

                    var t1 = h + sigma1 + ch + K[i] + W[i];
                    var t2 = sigma0 + maj;

                    h = g;
                    g = f;
                    f = e;
                    e = (d + t1) | 0;
                    d = c;
                    c = b;
                    b = a;
                    a = (t1 + t2) | 0;
                }

                // Intermediate hash value
                H[0] = (H[0] + a) | 0;
                H[1] = (H[1] + b) | 0;
                H[2] = (H[2] + c) | 0;
                H[3] = (H[3] + d) | 0;
                H[4] = (H[4] + e) | 0;
                H[5] = (H[5] + f) | 0;
                H[6] = (H[6] + g) | 0;
                H[7] = (H[7] + h) | 0;
            },

            _doFinalize: function () {
                // Shortcuts
                var data = this._data;
                var dataWords = data.words;

                var nBitsTotal = this._nDataBytes * 8;
                var nBitsLeft = data.sigBytes * 8;

                // Add padding
                dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
                dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
                dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
                data.sigBytes = dataWords.length * 4;

                // Hash final blocks
                this._process();

                // Return final computed hash
                return this._hash;
            },

            clone: function () {
                var clone = Hasher.clone.call(this);
                clone._hash = this._hash.clone();

                return clone;
            }
        });

        /**
         * Shortcut function to the hasher's object interface.
         *
         * @param {WordArray|string} message The message to hash.
         *
         * @return {WordArray} The hash.
         *
         * @static
         *
         * @example
         *
         *     var hash = CryptoJS.SHA256('message');
         *     var hash = CryptoJS.SHA256(wordArray);
         */
        C.SHA256 = Hasher._createHelper(SHA256);

        /**
         * Shortcut function to the HMAC's object interface.
         *
         * @param {WordArray|string} message The message to hash.
         * @param {WordArray|string} key The secret key.
         *
         * @return {WordArray} The HMAC.
         *
         * @static
         *
         * @example
         *
         *     var hmac = CryptoJS.HmacSHA256(message, key);
         */
        C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
    }(Math));

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    (function () {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var Base = C_lib.Base;
        var C_enc = C.enc;
        var Utf8 = C_enc.Utf8;
        var C_algo = C.algo;

        /**
         * HMAC algorithm.
         */
        var HMAC = C_algo.HMAC = Base.extend({
            /**
             * Initializes a newly created HMAC.
             *
             * @param {Hasher} hasher The hash algorithm to use.
             * @param {WordArray|string} key The secret key.
             *
             * @example
             *
             *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
             */
            init: function (hasher, key) {
                // Init hasher
                hasher = this._hasher = new hasher.init();

                // Convert string to WordArray, else assume WordArray already
                if (typeof key == 'string') {
                    key = Utf8.parse(key);
                }

                // Shortcuts
                var hasherBlockSize = hasher.blockSize;
                var hasherBlockSizeBytes = hasherBlockSize * 4;

                // Allow arbitrary length keys
                if (key.sigBytes > hasherBlockSizeBytes) {
                    key = hasher.finalize(key);
                }

                // Clamp excess bits
                key.clamp();

                // Clone key for inner and outer pads
                var oKey = this._oKey = key.clone();
                var iKey = this._iKey = key.clone();

                // Shortcuts
                var oKeyWords = oKey.words;
                var iKeyWords = iKey.words;

                // XOR keys with pad constants
                for (var i = 0; i < hasherBlockSize; i++) {
                    oKeyWords[i] ^= 0x5c5c5c5c;
                    iKeyWords[i] ^= 0x36363636;
                }
                oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

                // Set initial values
                this.reset();
            },

            /**
             * Resets this HMAC to its initial state.
             *
             * @example
             *
             *     hmacHasher.reset();
             */
            reset: function () {
                // Shortcut
                var hasher = this._hasher;

                // Reset
                hasher.reset();
                hasher.update(this._iKey);
            },

            /**
             * Updates this HMAC with a message.
             *
             * @param {WordArray|string} messageUpdate The message to append.
             *
             * @return {HMAC} This HMAC instance.
             *
             * @example
             *
             *     hmacHasher.update('message');
             *     hmacHasher.update(wordArray);
             */
            update: function (messageUpdate) {
                this._hasher.update(messageUpdate);

                // Chainable
                return this;
            },

            /**
             * Finalizes the HMAC computation.
             * Note that the finalize operation is effectively a destructive, read-once operation.
             *
             * @param {WordArray|string} messageUpdate (Optional) A final message update.
             *
             * @return {WordArray} The HMAC.
             *
             * @example
             *
             *     var hmac = hmacHasher.finalize();
             *     var hmac = hmacHasher.finalize('message');
             *     var hmac = hmacHasher.finalize(wordArray);
             */
            finalize: function (messageUpdate) {
                // Shortcut
                var hasher = this._hasher;

                // Compute HMAC
                var innerHash = hasher.finalize(messageUpdate);
                hasher.reset();
                var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

                return hmac;
            }
        });
    }());

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    /**
     * A noop padding strategy.
     */
    CryptoJS.pad.NoPadding = {
        pad: function () {
        },

        unpad: function () {
        }
    };

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */
    /**
     * Counter block mode.
     */
    CryptoJS.mode.CTR = (function () {
        var CTR = CryptoJS.lib.BlockCipherMode.extend();

        var Encryptor = CTR.Encryptor = CTR.extend({
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

        CTR.Decryptor = Encryptor;

        return CTR;
    }());

    ////////////////////////////////////////////////////////////////////////////////////////
      // Big Integer Library v. 5.5
      // Created 2000, last modified 2013
      // Leemon Baird
      // www.leemon.com
      //
      // Version history:
      // v 5.5  17 Mar 2013
      //   - two lines of a form like "if (x<0) x+=n" had the "if" changed to "while" to
      //     handle the case when x<-n. (Thanks to James Ansell for finding that bug)
      // v 5.4  3 Oct 2009
      //   - added "var i" to greaterShift() so i is not global. (Thanks to Péter Szabó for finding that bug)
      //
      // v 5.3  21 Sep 2009
      //   - added randProbPrime(k) for probable primes
      //   - unrolled loop in mont_ (slightly faster)
      //   - millerRabin now takes a bigInt parameter rather than an int
      //
      // v 5.2  15 Sep 2009
      //   - fixed capitalization in call to int2bigInt in randBigInt
      //     (thanks to Emili Evripidou, Reinhold Behringer, and Samuel Macaleese for finding that bug)
      //
      // v 5.1  8 Oct 2007
      //   - renamed inverseModInt_ to inverseModInt since it doesn't change its parameters
      //   - added functions GCD and randBigInt, which call GCD_ and randBigInt_
      //   - fixed a bug found by Rob Visser (see comment with his name below)
      //   - improved comments
      //
      // This file is public domain.   You can use it for any purpose without restriction.
      // I do not guarantee that it is correct, so use it at your own risk.  If you use
      // it for something interesting, I'd appreciate hearing about it.  If you find
      // any bugs or make any improvements, I'd appreciate hearing about those too.
      // It would also be nice if my name and URL were left in the comments.  But none
      // of that is required.
      //
      // This code defines a bigInt library for arbitrary-precision integers.
      // A bigInt is an array of integers storing the value in chunks of bpe bits,
      // little endian (buff[0] is the least significant word).
      // Negative bigInts are stored two's complement.  Almost all the functions treat
      // bigInts as nonnegative.  The few that view them as two's complement say so
      // in their comments.  Some functions assume their parameters have at least one
      // leading zero element. Functions with an underscore at the end of the name put
      // their answer into one of the arrays passed in, and have unpredictable behavior
      // in case of overflow, so the caller must make sure the arrays are big enough to
      // hold the answer.  But the average user should never have to call any of the
      // underscored functions.  Each important underscored function has a wrapper function
      // of the same name without the underscore that takes care of the details for you.
      // For each underscored function where a parameter is modified, that same variable
      // must not be used as another argument too.  So, you cannot square x by doing
      // multMod_(x,x,n).  You must use squareMod_(x,n) instead, or do y=dup(x); multMod_(x,y,n).
      // Or simply use the multMod(x,x,n) function without the underscore, where
      // such issues never arise, because non-underscored functions never change
      // their parameters; they always allocate new memory for the answer that is returned.
      //
      // These functions are designed to avoid frequent dynamic memory allocation in the inner loop.
      // For most functions, if it needs a BigInt as a local variable it will actually use
      // a global, and will only allocate to it only when it's not the right size.  This ensures
      // that when a function is called repeatedly with same-sized parameters, it only allocates
      // memory on the first call.
      //
      // Note that for cryptographic purposes, the calls to Math.random() must
      // be replaced with calls to a better pseudorandom number generator.
      //
      // In the following, "bigInt" means a bigInt with at least one leading zero element,
      // and "integer" means a nonnegative integer less than radix.  In some cases, integer
      // can be negative.  Negative bigInts are 2s complement.
      //
      // The following functions do not modify their inputs.
      // Those returning a bigInt, string, or Array will dynamically allocate memory for that value.
      // Those returning a boolean will return the integer 0 (false) or 1 (true).
      // Those returning boolean or int will not allocate memory except possibly on the first
      // time they're called with a given parameter size.
      //
      // bigInt  add(x,y)               //return (x+y) for bigInts x and y.
      // bigInt  addInt(x,n)            //return (x+n) where x is a bigInt and n is an integer.
      // string  bigInt2str(x,base)     //return a string form of bigInt x in a given base, with 2 <= base <= 95
      // int     bitSize(x)             //return how many bits long the bigInt x is, not counting leading zeros
      // bigInt  dup(x)                 //return a copy of bigInt x
      // boolean equals(x,y)            //is the bigInt x equal to the bigint y?
      // boolean equalsInt(x,y)         //is bigint x equal to integer y?
      // bigInt  expand(x,n)            //return a copy of x with at least n elements, adding leading zeros if needed
      // Array   findPrimes(n)          //return array of all primes less than integer n
      // bigInt  GCD(x,y)               //return greatest common divisor of bigInts x and y (each with same number of elements).
      // boolean greater(x,y)           //is x>y?  (x and y are nonnegative bigInts)
      // boolean greaterShift(x,y,shift)//is (x <<(shift*bpe)) > y?
      // bigInt  int2bigInt(t,n,m)      //return a bigInt equal to integer t, with at least n bits and m array elements
      // bigInt  inverseMod(x,n)        //return (x**(-1) mod n) for bigInts x and n.  If no inverse exists, it returns null
      // int     inverseModInt(x,n)     //return x**(-1) mod n, for integers x and n.  Return 0 if there is no inverse
      // boolean isZero(x)              //is the bigInt x equal to zero?
      // boolean millerRabin(x,b)       //does one round of Miller-Rabin base integer b say that bigInt x is possibly prime? (b is bigInt, 1<b<x)
      // boolean millerRabinInt(x,b)    //does one round of Miller-Rabin base integer b say that bigInt x is possibly prime? (b is int,    1<b<x)
      // bigInt  mod(x,n)               //return a new bigInt equal to (x mod n) for bigInts x and n.
      // int     modInt(x,n)            //return x mod n for bigInt x and integer n.
      // bigInt  mult(x,y)              //return x*y for bigInts x and y. This is faster when y<x.
      // bigInt  multMod(x,y,n)         //return (x*y mod n) for bigInts x,y,n.  For greater speed, let y<x.
      // boolean negative(x)            //is bigInt x negative?
      // bigInt  powMod(x,y,n)          //return (x**y mod n) where x,y,n are bigInts and ** is exponentiation.  0**0=1. Faster for odd n.
      // bigInt  randBigInt(n,s)        //return an n-bit random BigInt (n>=1).  If s=1, then the most significant of those n bits is set to 1.
      // bigInt  randTruePrime(k)       //return a new, random, k-bit, true prime bigInt using Maurer's algorithm.
      // bigInt  randProbPrime(k)       //return a new, random, k-bit, probable prime bigInt (probability it's composite less than 2^-80).
      // bigInt  str2bigInt(s,b,n,m)    //return a bigInt for number represented in string s in base b with at least n bits and m array elements
      // bigInt  sub(x,y)               //return (x-y) for bigInts x and y.  Negative answers will be 2s complement
      // bigInt  trim(x,k)              //return a copy of x with exactly k leading zero elements
      //
      //
      // The following functions each have a non-underscored version, which most users should call instead.
      // These functions each write to a single parameter, and the caller is responsible for ensuring the array
      // passed in is large enough to hold the result.
      //
      // void    addInt_(x,n)          //do x=x+n where x is a bigInt and n is an integer
      // void    add_(x,y)             //do x=x+y for bigInts x and y
      // void    copy_(x,y)            //do x=y on bigInts x and y
      // void    copyInt_(x,n)         //do x=n on bigInt x and integer n
      // void    GCD_(x,y)             //set x to the greatest common divisor of bigInts x and y, (y is destroyed).  (This never overflows its array).
      // boolean inverseMod_(x,n)      //do x=x**(-1) mod n, for bigInts x and n. Returns 1 (0) if inverse does (doesn't) exist
      // void    mod_(x,n)             //do x=x mod n for bigInts x and n. (This never overflows its array).
      // void    mult_(x,y)            //do x=x*y for bigInts x and y.
      // void    multMod_(x,y,n)       //do x=x*y  mod n for bigInts x,y,n.
      // void    powMod_(x,y,n)        //do x=x**y mod n, where x,y,n are bigInts (n is odd) and ** is exponentiation.  0**0=1.
      // void    randBigInt_(b,n,s)    //do b = an n-bit random BigInt. if s=1, then nth bit (most significant bit) is set to 1. n>=1.
      // void    randTruePrime_(ans,k) //do ans = a random k-bit true random prime (not just probable prime) with 1 in the msb.
      // void    sub_(x,y)             //do x=x-y for bigInts x and y. Negative answers will be 2s complement.
      //
      // The following functions do NOT have a non-underscored version.
      // They each write a bigInt result to one or more parameters.  The caller is responsible for
      // ensuring the arrays passed in are large enough to hold the results.
      //
      // void addShift_(x,y,ys)       //do x=x+(y<<(ys*bpe))
      // void carry_(x)               //do carries and borrows so each element of the bigInt x fits in bpe bits.
      // void divide_(x,y,q,r)        //divide x by y giving quotient q and remainder r
      // int  divInt_(x,n)            //do x=floor(x/n) for bigInt x and integer n, and return the remainder. (This never overflows its array).
      // int  eGCD_(x,y,d,a,b)        //sets a,b,d to positive bigInts such that d = GCD_(x,y) = a*x-b*y
      // void halve_(x)               //do x=floor(|x|/2)*sgn(x) for bigInt x in 2's complement.  (This never overflows its array).
      // void leftShift_(x,n)         //left shift bigInt x by n bits.  n<bpe.
      // void linComb_(x,y,a,b)       //do x=a*x+b*y for bigInts x and y and integers a and b
      // void linCombShift_(x,y,b,ys) //do x=x+b*(y<<(ys*bpe)) for bigInts x and y, and integers b and ys
      // void mont_(x,y,n,np)         //Montgomery multiplication (see comments where the function is defined)
      // void multInt_(x,n)           //do x=x*n where x is a bigInt and n is an integer.
      // void rightShift_(x,n)        //right shift bigInt x by n bits. (This never overflows its array).
      // void squareMod_(x,n)         //do x=x*x  mod n for bigInts x,n
      // void subShift_(x,y,ys)       //do x=x-(y<<(ys*bpe)). Negative answers will be 2s complement.
      //
      // The following functions are based on algorithms from the _Handbook of Applied Cryptography_
      //    powMod_()           = algorithm 14.94, Montgomery exponentiation
      //    eGCD_,inverseMod_() = algorithm 14.61, Binary extended GCD_
      //    GCD_()              = algorothm 14.57, Lehmer's algorithm
      //    mont_()             = algorithm 14.36, Montgomery multiplication
      //    divide_()           = algorithm 14.20  Multiple-precision division
      //    squareMod_()        = algorithm 14.16  Multiple-precision squaring
      //    randTruePrime_()    = algorithm  4.62, Maurer's algorithm
      //    millerRabin()       = algorithm  4.24, Miller-Rabin algorithm
      //
      // Profiling shows:
      //     randTruePrime_() spends:
      //         10% of its time in calls to powMod_()
      //         85% of its time in calls to millerRabin()
      //     millerRabin() spends:
      //         99% of its time in calls to powMod_()   (always with a base of 2)
      //     powMod_() spends:
      //         94% of its time in calls to mont_()  (almost always with x==y)
      //
      // This suggests there are several ways to speed up this library slightly:
      //     - convert powMod_ to use a Montgomery form of k-ary window (or maybe a Montgomery form of sliding window)
      //         -- this should especially focus on being fast when raising 2 to a power mod n
      //     - convert randTruePrime_() to use a minimum r of 1/3 instead of 1/2 with the appropriate change to the test
      //     - tune the parameters in randTruePrime_(), including c, m, and recLimit
      //     - speed up the single loop in mont_() that takes 95% of the runtime, perhaps by reducing checking
      //       within the loop when all the parameters are the same length.
      //
      // There are several ideas that look like they wouldn't help much at all:
      //     - replacing trial division in randTruePrime_() with a sieve (that speeds up something taking almost no time anyway)
      //     - increase bpe from 15 to 30 (that would help if we had a 32*32->64 multiplier, but not with JavaScript's 32*32->32)
      //     - speeding up mont_(x,y,n,np) when x==y by doing a non-modular, non-Montgomery square
      //       followed by a Montgomery reduction.  The intermediate answer will be twice as long as x, so that
      //       method would be slower.  This is unfortunate because the code currently spends almost all of its time
      //       doing mont_(x,x,...), both for randTruePrime_() and powMod_().  A faster method for Montgomery squaring
      //       would have a large impact on the speed of randTruePrime_() and powMod_().  HAC has a couple of poorly-worded
      //       sentences that seem to imply it's faster to do a non-modular square followed by a single
      //       Montgomery reduction, but that's obviously wrong.
      ////////////////////////////////////////////////////////////////////////////////////////

      //globals

      // The number of significant bits in the fraction of a JavaScript
      // floating-point number is 52, independent of platform.
      // See: https://github.com/arlolra/otr/issues/41

      var bpe = 26;          // bits stored per array element
      var radix = 1 << bpe;  // equals 2^bpe
      var mask = radix - 1;  // AND this with an array element to chop it down to bpe bits

      //the digits for converting to different bases
      var digitsStr='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_=!@#$%^&*()[]{}|;:,.<>/?`~ \\\'\"+-';

      var one=int2bigInt(1,1,1);     //constant used in powMod_()

      //the following global variables are scratchpad memory to
      //reduce dynamic memory allocation in the inner loop
      var t=new Array(0);
      var ss=t;       //used in mult_()
      var s0=t;       //used in multMod_(), squareMod_()
      var s3=t;       //used in powMod_()
      var s4=t, s5=t; //used in mod_()
      var s7=t;       //used in powMod_()
      var sa=t;       //used in mont_()
      var mr_x1=t, mr_r=t, mr_a=t;                                      //used in millerRabin()
      var eg_v=t, eg_u=t, eg_A=t, eg_B=t, eg_C=t, eg_D=t;               //used in eGCD_(), inverseMod_()

      var primes=t;

      ////////////////////////////////////////////////////////////////////////////////////////

      //return array of all primes less than integer n
      function findPrimes(n) {
        var i,s,p,ans;
        s=new Array(n);
        for (i=0;i<n;i++)
          s[i]=0;
        s[0]=2;
        p=0;    //first p elements of s are primes, the rest are a sieve
        for(;s[p]<n;) {                  //s[p] is the pth prime
          for(i=s[p]*s[p]; i<n; i+=s[p]) //mark multiples of s[p]
            s[i]=1;
          p++;
          s[p]=s[p-1]+1;
          for(; s[p]<n && s[s[p]]; s[p]++); //find next prime (where s[p]==0)
        }
        ans=new Array(p);
        for(i=0;i<p;i++)
          ans[i]=s[i];
        return ans;
      }

      //does a single round of Miller-Rabin base b consider x to be a possible prime?
      //x and b are bigInts with b<x
      function millerRabin(x,b) {
        var i,j,k,s;

        if (mr_x1.length!=x.length) {
          mr_x1=dup(x);
          mr_r=dup(x);
          mr_a=dup(x);
        }

        copy_(mr_a,b);
        copy_(mr_r,x);
        copy_(mr_x1,x);

        addInt_(mr_r,-1);
        addInt_(mr_x1,-1);

        //s=the highest power of two that divides mr_r

        /*
        k=0;
        for (i=0;i<mr_r.length;i++)
          for (j=1;j<mask;j<<=1)
            if (x[i] & j) {
              s=(k<mr_r.length+bpe ? k : 0);
               i=mr_r.length;
               j=mask;
            } else
              k++;
        */

        /* http://www.javascripter.net/math/primes/millerrabinbug-bigint54.htm */
        if (isZero(mr_r)) return 0;
        for (k=0; mr_r[k]==0; k++);
        for (i=1,j=2; mr_r[k]%j==0; j*=2,i++ );
        s = k*bpe + i - 1;
        /* end */

        if (s)
          rightShift_(mr_r,s);

        powMod_(mr_a,mr_r,x);

        if (!equalsInt(mr_a,1) && !equals(mr_a,mr_x1)) {
          j=1;
          while (j<=s-1 && !equals(mr_a,mr_x1)) {
            squareMod_(mr_a,x);
            if (equalsInt(mr_a,1)) {
              return 0;
            }
            j++;
          }
          if (!equals(mr_a,mr_x1)) {
            return 0;
          }
        }
        return 1;
      }

      //returns how many bits long the bigInt is, not counting leading zeros.
      function bitSize(x) {
        var j,z,w;
        for (j=x.length-1; (x[j]==0) && (j>0); j--);
        for (z=0,w=x[j]; w; (w>>=1),z++);
        z+=bpe*j;
        return z;
      }

      //return a copy of x with at least n elements, adding leading zeros if needed
      function expand(x,n) {
        var ans=int2bigInt(0,(x.length>n ? x.length : n)*bpe,0);
        copy_(ans,x);
        return ans;
      }

      //return a new bigInt equal to (x mod n) for bigInts x and n.
      function mod(x,n) {
        var ans=dup(x);
        mod_(ans,n);
        return trim(ans,1);
      }

      //return x*y for bigInts x and y. This is faster when y<x.
      function mult(x,y) {
        var ans=expand(x,x.length+y.length);
        mult_(ans,y);
        return trim(ans,1);
      }

      //return (x**y mod n) where x,y,n are bigInts and ** is exponentiation.  0**0=1. Faster for odd n.
      function powMod(x,y,n) {
        var ans=expand(x,n.length);
        powMod_(ans,trim(y,2),trim(n,2),0);  //this should work without the trim, but doesn't
        return trim(ans,1);
      }

      //return (x-y) for bigInts x and y.  Negative answers will be 2s complement
      function sub(x,y) {
        var ans=expand(x,(x.length>y.length ? x.length+1 : y.length+1));
        sub_(ans,y);
        return trim(ans,1);
      }

      //return (x+y) for bigInts x and y.
      function add(x,y) {
        var ans=expand(x,(x.length>y.length ? x.length+1 : y.length+1));
        add_(ans,y);
        return trim(ans,1);
      }

      //return (x**(-1) mod n) for bigInts x and n.  If no inverse exists, it returns null
      function inverseMod(x,n) {
        var ans=expand(x,n.length);
        var s;
        s=inverseMod_(ans,n);
        return s ? trim(ans,1) : null;
      }

      //return (x*y mod n) for bigInts x,y,n.  For greater speed, let y<x.
      function multMod(x,y,n) {
        var ans=expand(x,n.length);
        multMod_(ans,y,n);
        return trim(ans,1);
      }

      //Return an n-bit random BigInt (n>=1).  If s=1, then the most significant of those n bits is set to 1.
      function randBigInt(n,s) {
        var a,b;
        a=Math.floor((n-1)/bpe)+2; //# array elements to hold the BigInt with a leading 0 element
        b=int2bigInt(0,0,a);
        randBigInt_(b,n,s);
        return b;
      }

      //Set b to an n-bit random BigInt.  If s=1, then the most significant of those n bits is set to 1.
      //Array b must be big enough to hold the result. Must have n>=1
      function randBigInt_(b,n,s) {
        var i,a;
        for (i=0;i<b.length;i++)
          b[i]=0;
        a=Math.floor((n-1)/bpe)+1; //# array elements to hold the BigInt
        for (i=0;i<a;i++) {
          b[i]=randomBitInt(bpe);
        }
        b[a-1] &= (2<<((n-1)%bpe))-1;
        if (s==1)
          b[a-1] |= (1<<((n-1)%bpe));
      }

      //do x=x**(-1) mod n, for bigInts x and n.
      //If no inverse exists, it sets x to zero and returns 0, else it returns 1.
      //The x array must be at least as large as the n array.
      function inverseMod_(x,n) {
        var k=1+2*Math.max(x.length,n.length);

        if(!(x[0]&1)  && !(n[0]&1)) {  //if both inputs are even, then inverse doesn't exist
          copyInt_(x,0);
          return 0;
        }

        if (eg_u.length!=k) {
          eg_u=new Array(k);
          eg_v=new Array(k);
          eg_A=new Array(k);
          eg_B=new Array(k);
          eg_C=new Array(k);
          eg_D=new Array(k);
        }

        copy_(eg_u,x);
        copy_(eg_v,n);
        copyInt_(eg_A,1);
        copyInt_(eg_B,0);
        copyInt_(eg_C,0);
        copyInt_(eg_D,1);
        for (;;) {
          while(!(eg_u[0]&1)) {  //while eg_u is even
            halve_(eg_u);
            if (!(eg_A[0]&1) && !(eg_B[0]&1)) { //if eg_A==eg_B==0 mod 2
              halve_(eg_A);
              halve_(eg_B);
            } else {
              add_(eg_A,n);  halve_(eg_A);
              sub_(eg_B,x);  halve_(eg_B);
            }
          }

          while (!(eg_v[0]&1)) {  //while eg_v is even
            halve_(eg_v);
            if (!(eg_C[0]&1) && !(eg_D[0]&1)) { //if eg_C==eg_D==0 mod 2
              halve_(eg_C);
              halve_(eg_D);
            } else {
              add_(eg_C,n);  halve_(eg_C);
              sub_(eg_D,x);  halve_(eg_D);
            }
          }

          if (!greater(eg_v,eg_u)) { //eg_v <= eg_u
            sub_(eg_u,eg_v);
            sub_(eg_A,eg_C);
            sub_(eg_B,eg_D);
          } else {                   //eg_v > eg_u
            sub_(eg_v,eg_u);
            sub_(eg_C,eg_A);
            sub_(eg_D,eg_B);
          }

          if (equalsInt(eg_u,0)) {
            while (negative(eg_C)) //make sure answer is nonnegative
              add_(eg_C,n);
            copy_(x,eg_C);

            if (!equalsInt(eg_v,1)) { //if GCD_(x,n)!=1, then there is no inverse
              copyInt_(x,0);
              return 0;
            }
            return 1;
          }
        }
      }

      //return x**(-1) mod n, for integers x and n.  Return 0 if there is no inverse
      function inverseModInt(x,n) {
        var a=1,b=0;
        for (;;) {
          if (x==1) return a;
          if (x==0) return 0;
          b-=a*Math.floor(n/x);
          n%=x;

          if (n==1) return b; //to avoid negatives, change this b to n-b, and each -= to +=
          if (n==0) return 0;
          a-=b*Math.floor(x/n);
          x%=n;
        }
      }


      //is bigInt x negative?
      function negative(x) {
        return ((x[x.length-1]>>(bpe-1))&1);
      }


      //is (x << (shift*bpe)) > y?
      //x and y are nonnegative bigInts
      //shift is a nonnegative integer
      function greaterShift(x,y,shift) {
        var i, kx=x.length, ky=y.length;
        var k=((kx+shift)<ky) ? (kx+shift) : ky;
        for (i=ky-1-shift; i<kx && i>=0; i++)
          if (x[i]>0)
            return 1; //if there are nonzeros in x to the left of the first column of y, then x is bigger
        for (i=kx-1+shift; i<ky; i++)
          if (y[i]>0)
            return 0; //if there are nonzeros in y to the left of the first column of x, then x is not bigger
        for (i=k-1; i>=shift; i--)
          if      (x[i-shift]>y[i]) return 1;
          else if (x[i-shift]<y[i]) return 0;
        return 0;
      }

      //is x > y? (x and y both nonnegative)
      function greater(x,y) {
        var i;
        var k=(x.length<y.length) ? x.length : y.length;

        for (i=x.length;i<y.length;i++)
          if (y[i])
            return 0;  //y has more digits

        for (i=y.length;i<x.length;i++)
          if (x[i])
            return 1;  //x has more digits

        for (i=k-1;i>=0;i--)
          if (x[i]>y[i])
            return 1;
          else if (x[i]<y[i])
            return 0;
        return 0;
      }

      //divide x by y giving quotient q and remainder r.  (q=floor(x/y),  r=x mod y).  All 4 are bigints.
      //x must have at least one leading zero element.
      //y must be nonzero.
      //q and r must be arrays that are exactly the same length as x. (Or q can have more).
      //Must have x.length >= y.length >= 2.
      function divide_(x,y,q,r) {
        var kx, ky;
        var i,y1,y2,c,a,b;
        copy_(r,x);
        for (ky=y.length;y[ky-1]==0;ky--); //ky is number of elements in y, not including leading zeros

        //normalize: ensure the most significant element of y has its highest bit set
        b=y[ky-1];
        for (a=0; b; a++)
          b>>=1;
        a=bpe-a;  //a is how many bits to shift so that the high order bit of y is leftmost in its array element
        leftShift_(y,a);  //multiply both by 1<<a now, then divide both by that at the end
        leftShift_(r,a);

        //Rob Visser discovered a bug: the following line was originally just before the normalization.
        for (kx=r.length;r[kx-1]==0 && kx>ky;kx--); //kx is number of elements in normalized x, not including leading zeros

        copyInt_(q,0);                      // q=0
        while (!greaterShift(y,r,kx-ky)) {  // while (leftShift_(y,kx-ky) <= r) {
          subShift_(r,y,kx-ky);             //   r=r-leftShift_(y,kx-ky)
          q[kx-ky]++;                       //   q[kx-ky]++;
        }                                   // }

        for (i=kx-1; i>=ky; i--) {
          if (r[i]==y[ky-1])
            q[i-ky]=mask;
          else
            q[i-ky]=Math.floor((r[i]*radix+r[i-1])/y[ky-1]);

          //The following for(;;) loop is equivalent to the commented while loop,
          //except that the uncommented version avoids overflow.
          //The commented loop comes from HAC, which assumes r[-1]==y[-1]==0
          //  while (q[i-ky]*(y[ky-1]*radix+y[ky-2]) > r[i]*radix*radix+r[i-1]*radix+r[i-2])
          //    q[i-ky]--;
          for (;;) {
            y2=(ky>1 ? y[ky-2] : 0)*q[i-ky];
            c=y2;
            y2=y2 & mask;
            c = (c - y2) / radix;
            y1=c+q[i-ky]*y[ky-1];
            c=y1;
            y1=y1 & mask;
            c = (c - y1) / radix;

            if (c==r[i] ? y1==r[i-1] ? y2>(i>1 ? r[i-2] : 0) : y1>r[i-1] : c>r[i])
              q[i-ky]--;
            else
              break;
          }

          linCombShift_(r,y,-q[i-ky],i-ky);    //r=r-q[i-ky]*leftShift_(y,i-ky)
          if (negative(r)) {
            addShift_(r,y,i-ky);         //r=r+leftShift_(y,i-ky)
            q[i-ky]--;
          }
        }

        rightShift_(y,a);  //undo the normalization step
        rightShift_(r,a);  //undo the normalization step
      }

      //return x mod n for bigInt x and integer n.
      function modInt(x,n) {
        var i,c=0;
        for (i=x.length-1; i>=0; i--)
          c=(c*radix+x[i])%n;
        return c;
      }

      //convert the integer t into a bigInt with at least the given number of bits.
      //the returned array stores the bigInt in bpe-bit chunks, little endian (buff[0] is least significant word)
      //Pad the array with leading zeros so that it has at least minSize elements.
      //There will always be at least one leading 0 element.
      function int2bigInt(t,bits,minSize) {
        var k, buff;
        k=Math.ceil(bits/bpe)+1;
        k=minSize>k ? minSize : k;
        buff=new Array(k);
        copyInt_(buff,t);
        return buff;
      }

      //return the bigInt given a string representation in a given base.
      //Pad the array with leading zeros so that it has at least minSize elements.
      //If base=-1, then it reads in a space-separated list of array elements in decimal.
      //The array will always have at least one leading zero, unless base=-1.
      function str2bigInt(s,base,minSize) {
        var d, i, x, y, kk;
        var k=s.length;
        if (base==-1) { //comma-separated list of array elements in decimal
          x=new Array(0);
          for (;;) {
            y=new Array(x.length+1);
            for (i=0;i<x.length;i++)
              y[i+1]=x[i];
            y[0]=parseInt(s,10);
            x=y;
            d=s.indexOf(',',0);
            if (d<1)
              break;
            s=s.substring(d+1);
            if (s.length==0)
              break;
          }
          if (x.length<minSize) {
            y=new Array(minSize);
            copy_(y,x);
            return y;
          }
          return x;
        }

        // log2(base)*k
        var bb = base, p = 0;
        var b = base == 1 ? k : 0;
        while (bb > 1) {
          if (bb & 1) p = 1;
          b += k;
          bb >>= 1;
        }
        b += p*k;

        x=int2bigInt(0,b,0);
        for (i=0;i<k;i++) {
          d=digitsStr.indexOf(s.substring(i,i+1),0);
          if (base<=36 && d>=36)  //convert lowercase to uppercase if base<=36
            d-=26;
          if (d>=base || d<0) {   //stop at first illegal character
            break;
          }
          multInt_(x,base);
          addInt_(x,d);
        }

        for (k=x.length;k>0 && !x[k-1];k--); //strip off leading zeros
        k=minSize>k+1 ? minSize : k+1;
        y=new Array(k);
        kk=k<x.length ? k : x.length;
        for (i=0;i<kk;i++)
          y[i]=x[i];
        for (;i<k;i++)
          y[i]=0;
        return y;
      }

      //is bigint x equal to integer y?
      //y must have less than bpe bits
      function equalsInt(x,y) {
        var i;
        if (x[0]!=y)
          return 0;
        for (i=1;i<x.length;i++)
          if (x[i])
            return 0;
        return 1;
      }

      //are bigints x and y equal?
      //this works even if x and y are different lengths and have arbitrarily many leading zeros
      function equals(x,y) {
        var i;
        var k=x.length<y.length ? x.length : y.length;
        for (i=0;i<k;i++)
          if (x[i]!=y[i])
            return 0;
        if (x.length>y.length) {
          for (;i<x.length;i++)
            if (x[i])
              return 0;
        } else {
          for (;i<y.length;i++)
            if (y[i])
              return 0;
        }
        return 1;
      }

      //is the bigInt x equal to zero?
      function isZero(x) {
        var i;
        for (i=0;i<x.length;i++)
          if (x[i])
            return 0;
        return 1;
      }

      //returns a duplicate of bigInt x
      function dup(x) {
        var buff;
        buff=new Array(x.length);
        copy_(buff,x);
        return buff;
      }

      //do x=y on bigInts x and y.  x must be an array at least as big as y (not counting the leading zeros in y).
      function copy_(x,y) {
        var i;
        var k=x.length<y.length ? x.length : y.length;
        for (i=0;i<k;i++)
          x[i]=y[i];
        for (i=k;i<x.length;i++)
          x[i]=0;
      }

      //do x=y on bigInt x and integer y.
      function copyInt_(x,n) {
        var i,c;
        for (c=n,i=0;i<x.length;i++) {
          x[i]=c & mask;
          c>>=bpe;
        }
      }

      //do x=x+n where x is a bigInt and n is an integer.
      //x must be large enough to hold the result.
      function addInt_(x,n) {
        var i,k,c,b;
        x[0]+=n;
        k=x.length;
        c=0;
        for (i=0;i<k;i++) {
          c+=x[i];
          b=0;
          if (c<0) {
            b = c & mask;
            b = -((c - b) / radix);
            c+=b*radix;
          }
          x[i]=c & mask;
          c = ((c - x[i]) / radix) - b;
          if (!c) return; //stop carrying as soon as the carry is zero
        }
      }

      //right shift bigInt x by n bits.
      function rightShift_(x,n) {
        var i;
        var k=Math.floor(n/bpe);
        if (k) {
          for (i=0;i<x.length-k;i++) //right shift x by k elements
            x[i]=x[i+k];
          for (;i<x.length;i++)
            x[i]=0;
          n%=bpe;
        }
        for (i=0;i<x.length-1;i++) {
          x[i]=mask & ((x[i+1]<<(bpe-n)) | (x[i]>>n));
        }
        x[i]>>=n;
      }

      //do x=floor(|x|/2)*sgn(x) for bigInt x in 2's complement
      function halve_(x) {
        var i;
        for (i=0;i<x.length-1;i++) {
          x[i]=mask & ((x[i+1]<<(bpe-1)) | (x[i]>>1));
        }
        x[i]=(x[i]>>1) | (x[i] & (radix>>1));  //most significant bit stays the same
      }

      //left shift bigInt x by n bits.
      function leftShift_(x,n) {
        var i;
        var k=Math.floor(n/bpe);
        if (k) {
          for (i=x.length; i>=k; i--) //left shift x by k elements
            x[i]=x[i-k];
          for (;i>=0;i--)
            x[i]=0;
          n%=bpe;
        }
        if (!n)
          return;
        for (i=x.length-1;i>0;i--) {
          x[i]=mask & ((x[i]<<n) | (x[i-1]>>(bpe-n)));
        }
        x[i]=mask & (x[i]<<n);
      }

      //do x=x*n where x is a bigInt and n is an integer.
      //x must be large enough to hold the result.
      function multInt_(x,n) {
        var i,k,c,b;
        if (!n)
          return;
        k=x.length;
        c=0;
        for (i=0;i<k;i++) {
          c+=x[i]*n;
          b=0;
          if (c<0) {
            b = c & mask;
            b = -((c - b) / radix);
            c+=b*radix;
          }
          x[i]=c & mask;
          c = ((c - x[i]) / radix) - b;
        }
      }

      //do x=floor(x/n) for bigInt x and integer n, and return the remainder
      function divInt_(x,n) {
        var i,r=0,s;
        for (i=x.length-1;i>=0;i--) {
          s=r*radix+x[i];
          x[i]=Math.floor(s/n);
          r=s%n;
        }
        return r;
      }

      //do the linear combination x=a*x+b*(y<<(ys*bpe)) for bigInts x and y, and integers a, b and ys.
      //x must be large enough to hold the answer.
      function linCombShift_(x,y,b,ys) {
        var i,c,k,kk;
        k=x.length<ys+y.length ? x.length : ys+y.length;
        kk=x.length;
        for (c=0,i=ys;i<k;i++) {
          c+=x[i]+b*y[i-ys];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
        for (i=k;c && i<kk;i++) {
          c+=x[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
      }

      //do x=x+(y<<(ys*bpe)) for bigInts x and y, and integers a,b and ys.
      //x must be large enough to hold the answer.
      function addShift_(x,y,ys) {
        var i,c,k,kk;
        k=x.length<ys+y.length ? x.length : ys+y.length;
        kk=x.length;
        for (c=0,i=ys;i<k;i++) {
          c+=x[i]+y[i-ys];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
        for (i=k;c && i<kk;i++) {
          c+=x[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
      }

      //do x=x-(y<<(ys*bpe)) for bigInts x and y, and integers a,b and ys.
      //x must be large enough to hold the answer.
      function subShift_(x,y,ys) {
        var i,c,k,kk;
        k=x.length<ys+y.length ? x.length : ys+y.length;
        kk=x.length;
        for (c=0,i=ys;i<k;i++) {
          c+=x[i]-y[i-ys];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
        for (i=k;c && i<kk;i++) {
          c+=x[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
      }

      //do x=x-y for bigInts x and y.
      //x must be large enough to hold the answer.
      //negative answers will be 2s complement
      function sub_(x,y) {
        var i,c,k;
        k=x.length<y.length ? x.length : y.length;
        for (c=0,i=0;i<k;i++) {
          c+=x[i]-y[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
        for (i=k;c && i<x.length;i++) {
          c+=x[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
      }

      //do x=x+y for bigInts x and y.
      //x must be large enough to hold the answer.
      function add_(x,y) {
        var i,c,k;
        k=x.length<y.length ? x.length : y.length;
        for (c=0,i=0;i<k;i++) {
          c+=x[i]+y[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
        for (i=k;c && i<x.length;i++) {
          c+=x[i];
          x[i]=c & mask;
          c = (c - x[i]) / radix;
        }
      }

      //do x=x*y for bigInts x and y.  This is faster when y<x.
      function mult_(x,y) {
        var i;
        if (ss.length!=2*x.length)
          ss=new Array(2*x.length);
        copyInt_(ss,0);
        for (i=0;i<y.length;i++)
          if (y[i])
            linCombShift_(ss,x,y[i],i);   //ss=1*ss+y[i]*(x<<(i*bpe))
        copy_(x,ss);
      }

      //do x=x mod n for bigInts x and n.
      function mod_(x,n) {
        if (s4.length!=x.length)
          s4=dup(x);
        else
          copy_(s4,x);
        if (s5.length!=x.length)
          s5=dup(x);
        divide_(s4,n,s5,x);  //x = remainder of s4 / n
      }

      //do x=x*y mod n for bigInts x,y,n.
      //for greater speed, let y<x.
      function multMod_(x,y,n) {
        var i;
        if (s0.length!=2*x.length)
          s0=new Array(2*x.length);
        copyInt_(s0,0);
        for (i=0;i<y.length;i++)
          if (y[i])
            linCombShift_(s0,x,y[i],i);   //s0=1*s0+y[i]*(x<<(i*bpe))
        mod_(s0,n);
        copy_(x,s0);
      }

      //do x=x*x mod n for bigInts x,n.
      function squareMod_(x,n) {
        var i,j,c,kx,k;
        for (kx=x.length; kx>0 && !x[kx-1]; kx--);  //ignore leading zeros in x
        k=kx>n.length ? 2*kx : 2*n.length; //k=# elements in the product, which is twice the elements in the larger of x and n
        if (s0.length!=k)
          s0=new Array(k);
        copyInt_(s0,0);
        for (i=0;i<kx;i++) {
          c=s0[2*i]+x[i]*x[i];
          s0[2*i]=c & mask;
          c = (c - s0[2*i]) / radix;
          for (j=i+1;j<kx;j++) {
            c=s0[i+j]+2*x[i]*x[j]+c;
            s0[i+j]=(c & mask);
            c = (c - s0[i+j]) / radix;
          }
          s0[i+kx]=c;
        }
        mod_(s0,n);
        copy_(x,s0);
      }

      //return x with exactly k leading zero elements
      function trim(x,k) {
        var i,y;
        for (i=x.length; i>0 && !x[i-1]; i--);
        y=new Array(i+k);
        copy_(y,x);
        return y;
      }

      //do x=x**y mod n, where x,y,n are bigInts and ** is exponentiation.  0**0=1.
      //this is faster when n is odd.  x usually needs to have as many elements as n.
      function powMod_(x,y,n) {
        var k1,k2,kn,np;
        if(s7.length!=n.length)
          s7=dup(n);

        //for even modulus, use a simple square-and-multiply algorithm,
        //rather than using the more complex Montgomery algorithm.
        if ((n[0]&1)==0) {
          copy_(s7,x);
          copyInt_(x,1);
          while(!equalsInt(y,0)) {
            if (y[0]&1)
              multMod_(x,s7,n);
            divInt_(y,2);
            squareMod_(s7,n);
          }
          return;
        }

        //calculate np from n for the Montgomery multiplications
        copyInt_(s7,0);
        for (kn=n.length;kn>0 && !n[kn-1];kn--);
        np=radix-inverseModInt(modInt(n,radix),radix);
        s7[kn]=1;
        multMod_(x ,s7,n);   // x = x * 2**(kn*bp) mod n

        if (s3.length!=x.length)
          s3=dup(x);
        else
          copy_(s3,x);

        for (k1=y.length-1;k1>0 & !y[k1]; k1--);  //k1=first nonzero element of y
        if (y[k1]==0) {  //anything to the 0th power is 1
          copyInt_(x,1);
          return;
        }
        for (k2=1<<(bpe-1);k2 && !(y[k1] & k2); k2>>=1);  //k2=position of first 1 bit in y[k1]
        for (;;) {
          if (!(k2>>=1)) {  //look at next bit of y
            k1--;
            if (k1<0) {
              mont_(x,one,n,np);
              return;
            }
            k2=1<<(bpe-1);
          }
          mont_(x,x,n,np);

          if (k2 & y[k1]) //if next bit is a 1
            mont_(x,s3,n,np);
        }
      }


      //do x=x*y*Ri mod n for bigInts x,y,n,
      //  where Ri = 2**(-kn*bpe) mod n, and kn is the
      //  number of elements in the n array, not
      //  counting leading zeros.
      //x array must have at least as many elemnts as the n array
      //It's OK if x and y are the same variable.
      //must have:
      //  x,y < n
      //  n is odd
      //  np = -(n^(-1)) mod radix
      function mont_(x,y,n,np) {
        var i,j,c,ui,t,t2,ks;
        var kn=n.length;
        var ky=y.length;

        if (sa.length!=kn)
          sa=new Array(kn);

        copyInt_(sa,0);

        for (;kn>0 && n[kn-1]==0;kn--); //ignore leading zeros of n
        for (;ky>0 && y[ky-1]==0;ky--); //ignore leading zeros of y
        ks=sa.length-1; //sa will never have more than this many nonzero elements.

        //the following loop consumes 95% of the runtime for randTruePrime_() and powMod_() for large numbers
        for (i=0; i<kn; i++) {
          t=sa[0]+x[i]*y[0];
          ui=((t & mask) * np) & mask;  //the inner "& mask" was needed on Safari (but not MSIE) at one time
          c=(t+ui*n[0]);
          c = (c - (c & mask)) / radix;
          t=x[i];

          //do sa=(sa+x[i]*y+ui*n)/b   where b=2**bpe.  Loop is unrolled 5-fold for speed
          j=1;
          for (;j<ky-4;) {
            c+=sa[j]+ui*n[j]+t*y[j]; t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j]+t*y[j]; t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j]+t*y[j]; t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j]+t*y[j]; t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j]+t*y[j]; t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
          }
          for (;j<ky;)   {
            c+=sa[j]+ui*n[j]+t*y[j]; t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
          }
          for (;j<kn-4;) {
            c+=sa[j]+ui*n[j];        t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j];        t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j];        t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j];        t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
            c+=sa[j]+ui*n[j];        t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
          }
          for (;j<kn;)   {
            c+=sa[j]+ui*n[j];        t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
          }
          for (;j<ks;)   {
            c+=sa[j];                t2=sa[j-1]=c & mask; c=(c-t2)/radix; j++;
          }
          sa[j-1]=c & mask;
        }

        if (!greater(n,sa))
          sub_(sa,n);
        copy_(x,sa);
      }

      // computes 2^m as a bigInt
      function twoToThe(m) {
        var b = Math.floor(m / bpe) + 2;
        var t = new Array(b);
        for (var i = 0; i < b; i++) t[i] = 0;
        t[b - 2] = 1 << (m % bpe);
        return t
      }

      // cache these results for faster lookup
      var _num2bin = (function () {
        var i = 0, _num2bin= {};
        for (; i < 0x100; ++i) {
          _num2bin[i] = String.fromCharCode(i);  // 0 -> "\00"
        }
        return _num2bin
      }());

      // serialize a bigInt to an ascii string
      // padded up to pad length
      function bigInt2bits(bi, pad) {
        pad || (pad = 0);
        bi = dup(bi);
        var ba = '';
        while (!isZero(bi)) {
          ba = _num2bin[bi[0] & 0xff] + ba;
          rightShift_(bi, 8);
        }
        while (ba.length < pad) {
          ba = '\x00' + ba;
        }
        return ba
      }

      // converts a byte array to a bigInt
      function ba2bigInt(data) {
        var mpi = str2bigInt('0', 10, data.length);
        data.forEach(function (d, i) {
          if (i) leftShift_(mpi, 8);
          mpi[0] |= d;
        });
        return mpi
      }

      // returns a function that returns an array of n bytes
      var randomBytes = (function () {

        // in node
        if ( typeof crypto !== 'undefined' &&
          typeof crypto.randomBytes === 'function' ) {
          return function (n) {
            try {
              var buf = crypto.randomBytes(n);
            } catch (e) { throw e }
            return Array.prototype.slice.call(buf, 0)
          }
        }

        // in browser
        else if (typeof crypto !== 'undefined' &&
          typeof crypto.getRandomValues === 'function' ) {
          return function (n) {
            var buf = new Uint8Array(n);
            crypto.getRandomValues(buf);
            return Array.prototype.slice.call(buf, 0)
          }
        }

        // err
        else {
          throw new Error('Keys should not be generated without CSPRNG.')
        }

      }());

      // Salsa 20 in webworker needs a 40 byte seed
      function getSeed() {
        return randomBytes(40)
      }

      // returns a single random byte
      function randomByte() {
        return randomBytes(1)[0]
      }

      // returns a k-bit random integer
      function randomBitInt(k) {
        if (k > 31) throw new Error("Too many bits.")
        var i = 0, r = 0;
        var b = Math.floor(k / 8);
        var mask = (1 << (k % 8)) - 1;
        if (mask) r = randomByte() & mask;
        for (; i < b; i++)
          r = (256 * r) + randomByte();
        return r
      }

    var HLP = {};

      // data types (byte lengths)
      var DTS = {
          BYTE  : 1
        , SHORT : 2
        , INT   : 4
        , CTR   : 8
        , MAC   : 20
        , SIG   : 40
      };

      // otr message wrapper begin and end
      var WRAPPER_BEGIN = "?OTR"
        , WRAPPER_END   = ".";

      var TWO = str2bigInt('2', 10);

      HLP.debug = function (msg) {
        // used as HLP.debug.call(ctx, msg)
        if ( this.debug &&
             typeof this.debug !== 'function' &&
             typeof console !== 'undefined'
        ) console.log(msg);
      };

      HLP.extend = function (child, parent) {
        for (var key in parent) {
          if (Object.hasOwnProperty.call(parent, key))
            child[key] = parent[key];
        }
        function Ctor() { this.constructor = child; }
        Ctor.prototype = parent.prototype;
        child.prototype = new Ctor();
        child.__super__ = parent.prototype;
      };

      // assumes 32-bit
      function intCompare(x, y) {
        var z = ~(x ^ y);
        z &= z >> 16;
        z &= z >> 8;
        z &= z >> 4;
        z &= z >> 2;
        z &= z >> 1;
        return z & 1
      }

      // constant-time string comparison
      HLP.compare = function (str1, str2) {
        if (str1.length !== str2.length)
          return false
        var i = 0, result = 0;
        for (; i < str1.length; i++)
          result |= str1[i].charCodeAt(0) ^ str2[i].charCodeAt(0);
        return intCompare(result, 0)
      };

      HLP.randomExponent = function () {
        return randBigInt(1536)
      };

      HLP.smpHash = function (version, fmpi, smpi) {
        var sha256 = C.algo.SHA256.create();
        sha256.update(C.enc.Latin1.parse(HLP.packBytes(version, DTS.BYTE)));
        sha256.update(C.enc.Latin1.parse(HLP.packMPI(fmpi)));
        if (smpi) sha256.update(C.enc.Latin1.parse(HLP.packMPI(smpi)));
        var hash = sha256.finalize();
        return HLP.bits2bigInt(hash.toString(C.enc.Latin1))
      };

      HLP.makeMac = function (aesctr, m) {
        var pass = C.enc.Latin1.parse(m);
        var mac = C.HmacSHA256(C.enc.Latin1.parse(aesctr), pass);
        return HLP.mask(mac.toString(C.enc.Latin1), 0, 160)
      };

      HLP.make1Mac = function (aesctr, m) {
        var pass = C.enc.Latin1.parse(m);
        var mac = C.HmacSHA1(C.enc.Latin1.parse(aesctr), pass);
        return mac.toString(C.enc.Latin1)
      };

      HLP.encryptAes = function (msg, c, iv) {
        var opts = {
            mode: C.mode.CTR
          , iv: C.enc.Latin1.parse(iv)
          , padding: C.pad.NoPadding
        };
        var aesctr = C.AES.encrypt(
            msg
          , C.enc.Latin1.parse(c)
          , opts
        );
        var aesctr_decoded = C.enc.Base64.parse(aesctr.toString());
        return C.enc.Latin1.stringify(aesctr_decoded)
      };

      HLP.decryptAes = function (msg, c, iv) {
        msg = C.enc.Latin1.parse(msg);
        var opts = {
            mode: C.mode.CTR
          , iv: C.enc.Latin1.parse(iv)
          , padding: C.pad.NoPadding
        };
        return C.AES.decrypt(
            C.enc.Base64.stringify(msg)
          , C.enc.Latin1.parse(c)
          , opts
        )
      };

      HLP.multPowMod = function (a, b, c, d, e) {
        return multMod(powMod(a, b, e), powMod(c, d, e), e)
      };

      HLP.ZKP = function (v, c, d, e) {
        return equals(c, HLP.smpHash(v, d, e))
      };

      // greater than, or equal
      HLP.GTOE = function (a, b) {
        return (equals(a, b) || greater(a, b))
      };

      HLP.between = function (x, a, b) {
        return (greater(x, a) && greater(b, x))
      };

      HLP.checkGroup = function (g, N_MINUS_2) {
        return HLP.GTOE(g, TWO) && HLP.GTOE(N_MINUS_2, g)
      };

      HLP.h1 = function (b, secbytes) {
        var sha1 = C.algo.SHA1.create();
        sha1.update(C.enc.Latin1.parse(b));
        sha1.update(C.enc.Latin1.parse(secbytes));
        return (sha1.finalize()).toString(C.enc.Latin1)
      };

      HLP.h2 = function (b, secbytes) {
        var sha256 = C.algo.SHA256.create();
        sha256.update(C.enc.Latin1.parse(b));
        sha256.update(C.enc.Latin1.parse(secbytes));
        return (sha256.finalize()).toString(C.enc.Latin1)
      };

      HLP.mask = function (bytes, start, n) {
        return bytes.substr(start / 8, n / 8)
      };

      var _toString = String.fromCharCode;
      HLP.packBytes = function (val, bytes) {
        val = val.toString(16);
        var nex, res = '';  // big-endian, unsigned long
        for (; bytes > 0; bytes--) {
          nex = val.length ? val.substr(-2, 2) : '0';
          val = val.substr(0, val.length - 2);
          res = _toString(parseInt(nex, 16)) + res;
        }
        return res
      };

      HLP.packINT = function (d) {
        return HLP.packBytes(d, DTS.INT)
      };

      HLP.packCtr = function (d) {
        return HLP.padCtr(HLP.packBytes(d, DTS.CTR))
      };

      HLP.padCtr = function (ctr) {
        return ctr + '\x00\x00\x00\x00\x00\x00\x00\x00'
      };

      HLP.unpackCtr = function (d) {
        d = HLP.toByteArray(d.substring(0, 8));
        return HLP.unpack(d)
      };

      HLP.unpack = function (arr) {
        var val = 0, i = 0, len = arr.length;
        for (; i < len; i++) {
          val = (val * 256) + arr[i];
        }
        return val
      };

      HLP.packData = function (d) {
        return HLP.packINT(d.length) + d
      };

      HLP.bits2bigInt = function (bits) {
        bits = HLP.toByteArray(bits);
        return ba2bigInt(bits)
      };

      HLP.packMPI = function (mpi) {
        return HLP.packData(bigInt2bits(trim(mpi, 0)))
      };

      HLP.packSHORT = function (short) {
        return HLP.packBytes(short, DTS.SHORT)
      };

      HLP.unpackSHORT = function (short) {
        short = HLP.toByteArray(short);
        return HLP.unpack(short)
      };

      HLP.packTLV = function (type, value) {
        return HLP.packSHORT(type) + HLP.packSHORT(value.length) + value
      };

      HLP.readLen = function (msg) {
        msg = HLP.toByteArray(msg.substring(0, 4));
        return HLP.unpack(msg)
      };

      HLP.readData = function (data) {
        var n = HLP.unpack(data.splice(0, 4));
        return [n, data]
      };

      HLP.readMPI = function (data) {
        data = HLP.toByteArray(data);
        data = HLP.readData(data);
        return ba2bigInt(data[1])
      };

      HLP.packMPIs = function (arr) {
        return arr.reduce(function (prv, cur) {
          return prv + HLP.packMPI(cur)
        }, '')
      };

      HLP.unpackMPIs = function (num, mpis) {
        var i = 0, arr = [];
        for (; i < num; i++) arr.push('MPI');
        return (HLP.splitype(arr, mpis)).map(function (m) {
          return HLP.readMPI(m)
        })
      };

      HLP.wrapMsg = function (msg, fs, v3, our_it, their_it) {
        msg = C.enc.Base64.stringify(C.enc.Latin1.parse(msg));
        msg = WRAPPER_BEGIN + ":" + msg + WRAPPER_END;

        var its;
        if (v3) {
          its = '|';
          its += (HLP.readLen(our_it)).toString(16);
          its += '|';
          its += (HLP.readLen(their_it)).toString(16);
        }

        if (!fs) return [null, msg]

        var n = Math.ceil(msg.length / fs);
        if (n > 65535) return ['Too many fragments']
        if (n == 1) return [null, msg]

        var k, bi, ei, frag, mf, mfs = [];
        for (k = 1; k <= n; k++) {
          bi = (k - 1) * fs;
          ei = k * fs;
          frag = msg.slice(bi, ei);
          mf = WRAPPER_BEGIN;
          if (v3) mf += its;
          mf += ',' + k + ',';
          mf += n + ',';
          mf += frag + ',';
          mfs.push(mf);
        }

        return [null, mfs]
      };

      HLP.splitype = function splitype(arr, msg) {
        var data = [];
        arr.forEach(function (a) {
          var str;
          switch (a) {
            case 'PUBKEY':
              str = splitype(['SHORT', 'MPI', 'MPI', 'MPI', 'MPI'], msg).join('');
              break
            case 'DATA':  // falls through
            case 'MPI':
              str = msg.substring(0, HLP.readLen(msg) + 4);
              break
            default:
              str = msg.substring(0, DTS[a]);
          }
          data.push(str);
          msg = msg.substring(str.length);
        });
        return data
      };

      // https://github.com/msgpack/msgpack-javascript/blob/master/msgpack.js

      var _bin2num = (function () {
        var i = 0, _bin2num = {};
        for (; i < 0x100; ++i) {
          _bin2num[String.fromCharCode(i)] = i;  // "\00" -> 0x00
        }
        for (i = 0x80; i < 0x100; ++i) {  // [Webkit][Gecko]
          _bin2num[String.fromCharCode(0xf700 + i)] = i;  // "\f780" -> 0x80
        }
        return _bin2num
      }());

      HLP.toByteArray = function (data) {
        var rv = []
          , ary = data.split("")
          , i = -1
          , iz = ary.length
          , remain = iz % 8;

        while (remain--) {
          ++i;
          rv[i] = _bin2num[ary[i]];
        }
        remain = iz >> 3;
        while (remain--) {
          rv.push(_bin2num[ary[++i]], _bin2num[ary[++i]],
                  _bin2num[ary[++i]], _bin2num[ary[++i]],
                  _bin2num[ary[++i]], _bin2num[ary[++i]],
                  _bin2num[ary[++i]], _bin2num[ary[++i]]);
        }
        return rv
      };

    var Webworker;

    if (typeof Worker !== 'undefined')
      Webworker = Worker;
    else if (typeof module !== 'undefined' && module.exports)
      Webworker = require('webworker-threads').Worker;
    else if (typeof window !== 'undefined' && typeof window.Worker !== 'undefined')
      Webworker = window.Worker;
    else
      throw "No webworker available"

    var Worker$1 = Webworker;

    var WWPath;
    if (typeof module !== 'undefined' && module.exports)
      WWPath = require('path').join(__dirname, '/dsa-webworker.js');
    else
      WWPath = 'dsa-webworker.js';

      var ZERO = str2bigInt('0', 10)
        , ONE = str2bigInt('1', 10)
        , TWO$1 = str2bigInt('2', 10)
        , KEY_TYPE = '\x00\x00';

      var DEBUG = false;
      function timer() {
        var start = (new Date()).getTime();
        return function (s) {
          return
          var t = (new Date()).getTime();
          console.log(s + ': ' + (t - start));
          start = t;
        }
      }

      function makeRandom(min, max) {
        var c = randBigInt(bitSize(max));
        if (!HLP.between(c, min, max)) return makeRandom(min, max)
        return c
      }

      // altered BigInt.randProbPrime()
      // n rounds of Miller Rabin (after trial division with small primes)
      var rpprb = [];
      function isProbPrime(k, n) {
        var i, B = 30000, l = bitSize(k);
        var primes$1 = primes;

        if (primes$1.length === 0)
          primes$1 = findPrimes(B);

        if (rpprb.length != k.length)
          rpprb = dup(k);

        // check ans for divisibility by small primes up to B
        for (i = 0; (i < primes$1.length) && (primes$1[i] <= B); i++)
          if (modInt(k, primes$1[i]) === 0 && !equalsInt(k, primes$1[i]))
            return 0

        // do n rounds of Miller Rabin, with random bases less than k
        for (i = 0; i < n; i++) {
          randBigInt_(rpprb, l, 0);
          while(!greater(k, rpprb))  // pick a random rpprb that's < k
            randBigInt_(rpprb, l, 0);
          if (!millerRabin(k, rpprb))
            return 0
        }

        return 1
      }

      var bit_lengths = {
          '1024': { N: 160, repeat: 40 }  // 40x should give 2^-80 confidence
        , '2048': { N: 224, repeat: 56 }
      };

      var primes$1 = {};

      // follows go lang http://golang.org/src/pkg/crypto/dsa/dsa.go
      // fips version was removed in 0c99af0df3e7
      function generatePrimes(bit_length) {

        var t = timer();  // for debugging

        // number of MR tests to perform
        var repeat = bit_lengths[bit_length].repeat;

        var N = bit_lengths[bit_length].N;

        var LM1 = twoToThe(bit_length - 1);
        var bl4 = 4 * bit_length;
        var brk = false;

        var q, p, rem, counter;
        for (;;) {

          q = randBigInt(N, 1);
          q[0] |= 1;

          if (!isProbPrime(q, repeat)) continue
          t('q');

          for (counter = 0; counter < bl4; counter++) {
            p = randBigInt(bit_length, 1);
            p[0] |= 1;

            rem = mod(p, q);
            rem = sub(rem, ONE);
            p = sub(p, rem);

            if (greater(LM1, p)) continue
            if (!isProbPrime(p, repeat)) continue

            t('p');
            primes$1[bit_length] = { p: p, q: q };
            brk = true;
            break
          }

          if (brk) break
        }

        var h = dup(TWO$1);
        var pm1 = sub(p, ONE);
        var e = multMod(pm1, inverseMod(q, p), p);

        var g;
        for (;;) {
          g = powMod(h, e, p);
          if (equals(g, ONE)) {
            h = add(h, ONE);
            continue
          }
          primes$1[bit_length].g = g;
          t('g');
          return
        }

        throw new Error('Unreachable!')
      }

      function DSA(obj, opts) {
        if (!(this instanceof DSA)) return new DSA(obj, opts)

        // options
        opts = opts || {};

        // inherit
        if (obj) {
          var self = this
          ;['p', 'q', 'g', 'y', 'x'].forEach(function (prop) {
            self[prop] = obj[prop];
          });
          this.type = obj.type || KEY_TYPE;
          return
        }

        // default to 1024
        var bit_length = parseInt(opts.bit_length ? opts.bit_length : 1024, 10);

        if (!bit_lengths[bit_length])
          throw new Error('Unsupported bit length.')

        // set primes
        if (!primes$1[bit_length])
          generatePrimes(bit_length);

        this.p = primes$1[bit_length].p;
        this.q = primes$1[bit_length].q;
        this.g = primes$1[bit_length].g;

        // key type
        this.type = KEY_TYPE;

        // private key
        this.x = makeRandom(ZERO, this.q);

        // public keys (p, q, g, y)
        this.y = powMod(this.g, this.x, this.p);

        // nocache?
        if (opts.nocache) primes$1[bit_length] = null;
      }

      DSA.prototype = {

        constructor: DSA,

        packPublic: function () {
          var str = this.type;
          str += HLP.packMPI(this.p);
          str += HLP.packMPI(this.q);
          str += HLP.packMPI(this.g);
          str += HLP.packMPI(this.y);
          return str
        },

        packPrivate: function () {
          var str = this.packPublic() + HLP.packMPI(this.x);
          str = C.enc.Latin1.parse(str);
          return str.toString(C.enc.Base64)
        },

        // http://www.imperialviolet.org/2013/06/15/suddendeathentropy.html
        generateNonce: function (m) {
          var priv = bigInt2bits(trim(this.x, 0));
          var rand = bigInt2bits(randBigInt(256));

          var sha256 = C.algo.SHA256.create();
          sha256.update(C.enc.Latin1.parse(priv));
          sha256.update(m);
          sha256.update(C.enc.Latin1.parse(rand));

          var hash = sha256.finalize();
          hash = HLP.bits2bigInt(hash.toString(C.enc.Latin1));
          rightShift_(hash, 256 - bitSize(this.q));

          return HLP.between(hash, ZERO, this.q) ? hash : this.generateNonce(m)
        },

        sign: function (m) {
          m = C.enc.Latin1.parse(m);
          var b = str2bigInt(m.toString(C.enc.Hex), 16);
          var k, r = ZERO, s = ZERO;
          while (isZero(s) || isZero(r)) {
            k = this.generateNonce(m);
            r = mod(powMod(this.g, k, this.p), this.q);
            if (isZero(r)) continue
            s = inverseMod(k, this.q);
            s = mult(s, add(b, mult(this.x, r)));
            s = mod(s, this.q);
          }
          return [r, s]
        },

        fingerprint: function () {
          var pk = this.packPublic();
          if (this.type === KEY_TYPE) pk = pk.substring(2);
          pk = C.enc.Latin1.parse(pk);
          return C.SHA1(pk).toString(C.enc.Hex)
        }

      };

      DSA.parsePublic = function (str, priv) {
        var fields = ['SHORT', 'MPI', 'MPI', 'MPI', 'MPI'];
        if (priv) fields.push('MPI');
        str = HLP.splitype(fields, str);
        var obj = {
            type: str[0]
          , p: HLP.readMPI(str[1])
          , q: HLP.readMPI(str[2])
          , g: HLP.readMPI(str[3])
          , y: HLP.readMPI(str[4])
        };
        if (priv) obj.x = HLP.readMPI(str[5]);
        return new DSA(obj)
      };

      function tokenizeStr(str) {
        var start, end;

        start = str.indexOf("(");
        end = str.lastIndexOf(")");

        if (start < 0 || end < 0)
          throw new Error("Malformed S-Expression")

        str = str.substring(start + 1, end);

        var splt = str.search(/\s/);
        var obj = {
            type: str.substring(0, splt)
          , val: []
        };

        str = str.substring(splt + 1, end);
        start = str.indexOf("(");

        if (start < 0) obj.val.push(str);
        else {

          var i, len, ss, es;
          while (start > -1) {
            i = start + 1;
            len = str.length;
            for (ss = 1, es = 0; i < len && es < ss; i++) {
              if (str[i] === "(") ss++;
              if (str[i] === ")") es++;
            }
            obj.val.push(tokenizeStr(str.substring(start, ++i)));
            str = str.substring(++i);
            start = str.indexOf("(");
          }

        }
        return obj
      }

      function parseLibotr(obj) {
        if (!obj.type) throw new Error("Parse error.")

        var o, val;
        if (obj.type === "privkeys") {
          o = [];
          obj.val.forEach(function (i) {
            o.push(parseLibotr(i));
          });
          return o
        }

        o = {};
        obj.val.forEach(function (i) {

          val = i.val[0];
          if (typeof val === "string") {

            if (val.indexOf("#") === 0) {
              val = val.substring(1, val.lastIndexOf("#"));
              val = str2bigInt(val, 16);
            }

          } else {
            val = parseLibotr(i);
          }

          o[i.type] = val;
        });

        return o
      }

      DSA.parsePrivate = function (str, libotr) {
        if (!libotr) {
          str = C.enc.Base64.parse(str);
          str = str.toString(C.enc.Latin1);
          return DSA.parsePublic(str, true)
        }
        // only returning the first key found
        return parseLibotr(tokenizeStr(str))[0]["private-key"].dsa
      };

      DSA.verify = function (key, m, r, s) {
        if (!HLP.between(r, ZERO, key.q) || !HLP.between(s, ZERO, key.q))
          return false

        var hm = C.enc.Latin1.parse(m);  // CryptoJS.SHA1(m)
        hm = str2bigInt(hm.toString(C.enc.Hex), 16);

        var w = inverseMod(s, key.q);
        var u1 = multMod(hm, w, key.q);
        var u2 = multMod(r, w, key.q);

        u1 = powMod(key.g, u1, key.p);
        u2 = powMod(key.y, u2, key.p);

        var v = mod(multMod(u1, u2, key.p), key.q);

        return equals(v, r)
      };

      DSA.createInWebWorker = function (options, cb) {
        var opts = {
            path: WWPath
          , seed: getSeed
        };
        if (options && typeof options === 'object')
          Object.keys(options).forEach(function (k) {
            opts[k] = options[k];
          });

        var worker = new Worker$1(opts.path);
        worker.onmessage = function (e) {
          var data = e.data;
          switch (data.type) {
            case "debug":
              return
              console.log(data.val);
              break;
            case "data":
              worker.terminate();
              cb(DSA.parsePrivate(data.val));
              break;
            default:
              throw new Error("Unrecognized type.")
          }
        };
        worker.postMessage({
            seed: opts.seed()
          , imports: opts.imports
          , debug: DEBUG
        });
      };

    function sendMsg(type, val) {
        postMessage({ type: type, val: val });
      }

      onmessage = function (e) {
        var data = e.data;

        if (data.debug) sendMsg('debug', 'DSA key creation started');
        var dsa;
        try {
          dsa = new DSA();
        } catch (e) {
          if (data.debug) sendMsg('debug', e.toString());
          return
        }
        if (data.debug) sendMsg('debug', 'DSA key creation finished');

        sendMsg('data', dsa.packPrivate());
      };

}));
