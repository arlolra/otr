
  var root = this
  return {
      OTR: root.OTR
    , DSA: root.DSA
  }

}

  var root = this
  if (typeof define === 'function' && define.amd) {
    define([
        "./dep/bigint"
      , "./dep/crypto"
      , "./dep/eventemitter"
    ], function (BigInt, CryptoJS, EventEmitter) {
      var root = {
          BigInt: BigInt
        , CryptoJS: CryptoJS
        , EventEmitter: EventEmitter
        , OTR: {}
        , DSA: {}
      }
      return OTR.call(root)
    })
  } else {
    root.OTR = {}
    root.DSA = {}
    OTR.call(root)
  }

}).call(this)