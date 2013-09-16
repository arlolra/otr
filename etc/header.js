;(function (root, factory) {

  if (typeof define === 'function' && define.amd) {
    define([
        "bigint"
      , "crypto"
      , "eventemitter"
    ], function (BigInt, CryptoJS, EventEmitter) {
      var root = {
          BigInt: BigInt
        , CryptoJS: CryptoJS
        , EventEmitter: EventEmitter
        , OTR: {}
        , DSA: {}
      }
      return factory.call(root)
    })
  } else {
    root.OTR = {}
    root.DSA = {}
    factory.call(root)
  }

}(this, function () {
