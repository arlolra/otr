;(function (root, factory) {

  if (typeof define === 'function' && define.amd) {
    define([
        "./dep/bigint"
      , "./dep/crypto"
      , "./dep/eventemitter"
    ], function (BigInt, CryptoJS, EventEmitter) {
      return factory({
          BigInt: BigInt
        , CryptoJS: CryptoJS
        , EventEmitter: EventEmitter
        , OTR: {}
        , DSA: {}
      })
    })
  } else {
    root.OTR = {}
    root.DSA = {}
    factory(root)
  }

}(this, function (root) {
