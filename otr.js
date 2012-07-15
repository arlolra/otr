var Crypto = require('./vendor/aes.js')
  , BigInt = require('./vendor/bigint.js')
  , DH = require('./dh.json')
  , hlp = require('./helpers.js')

// diffie-hellman modulus and generator
// see group 5, RFC 3526
var G = BigInt.str2bigInt(DH.G, 10)
var N = BigInt.str2bigInt(DH.N, 16)

module.exports = OTR

function OTR() {
  if (!(this instanceof OTR)) return new OTR()

  // bind methods
  var self = this
  ;['sendMsg', 'receiveMsg'].forEach(function (meth) {
    self[meth] = self[meth].bind(self)
  })
}

OTR.prototype = {

  constructor: OTR,

  initiateAKE: function (cb) {
    var r = hlp.randomValue()
    var x = BigInt.randBigInt(320)
    var send = {}

    this.sendMsg(send, cb)
  },

  sendMsg: function (send, cb) {
    console.log('sending')
    cb(send, this.receiveMsg)
  },

  receiveMsg: function (msg, cb) {
    if (typeof cb !== 'function')
      throw new Error('Nowhere to go?')
  }

}