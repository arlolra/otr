var AES = require('./vendor/aes.js')
  , SHA256 = require('./vendor/sha256.js')
  , BigInt = require('./vendor/bigint.js')
  , DH = require('./dh.json')
  , hlp = require('./helpers.js')

// ctr mode
require('./vendor/mode-ctr.js')(AES)

// otr message states
var MSGSTATE_PLAINTEXT = 0
  , MSGSTATE_ENCRYPTED = 1
  , MSGSTATE_FINISHED = 2

// otr authentication states
var AUTHSTATE_NONE = 0
  , AUTHSTATE_AWAITING_DHKEY = 1
  , AUTHSTATE_AWAITING_REVEALSIG = 2
  , AUTHSTATE_AWAITING_SIG = 3
  , AUTHSTATE_V1_SETUP = 4

// diffie-hellman modulus and generator
// see group 5, RFC 3526
var G = BigInt.str2bigInt(DH.G, 10)
var N = BigInt.str2bigInt(DH.N, 16)
var TWO = BigInt.str2bigInt('2', 10)
var N_MINUS_2 = BigInt.sub(N, TWO)

module.exports = OTR

function OTR() {
  if (!(this instanceof OTR)) return new OTR()

  this.init()

  // bind methods
  var self = this
  ;['sendMsg', 'receiveMsg'].forEach(function (meth) {
    self[meth] = self[meth].bind(self)
  })
}

OTR.prototype = {

  constructor: OTR,

  init: function () {
    this.msgstate = MSGSTATE_PLAINTEXT
    this.authstate = AUTHSTATE_NONE
    this.ALLOW_V1 = false
    this.ALLOW_V2 = true
  },

  handleAKE: function (msg, cb) {
    var reply = true
      , send = {}

    switch (msg.type) {

      case '0x02':
        // d-h key message
        this.y = BigInt.randBigInt(320)
        send.gy = this.gy = BigInt.powMod(G, this.y, N)
        this.encrypted = msg.encrypted
        this.hashed = msg.hashed
        send.type = '0x0a'
        send.version = '0x0002'
        break

      case '0x0a':
        // reveal signature message

        // verify gy is legal 2 <= gy <= N-2
        if (!( hlp.GTOE(msg.gy, TWO) && hlp.GTOE(N_MINUS_2, msg.gy) ))
          return this.error('Illegal g^y.')

        this.s = BigInt.powMod(msg.gy, this.x, N)
        console.log(BigInt.bigInt2str(this.s, 10))

        send.type = '0x11'
        send.version = '0x0002'
        reply = false
        break

      case '0x11':
        // signature message
        send.type = '0x12'
        send.version = '0x0002'
        break

      case '0x12':
        // data message
        send.type = '0x03'
        send.version = '0x0002'
        break

      default:
        this.error('Invalid message type.')
        reply = false

    }

    if (reply) this.sendMsg(send, cb)
  },

  initiateAKE: function (cb) {

    // d-h commit message
    var send = {
       type: '0x02'
     , version: '0x0002'
    }

    this.r = hlp.randomValue()
    this.x = BigInt.randBigInt(320)

    this.gx = BigInt.powMod(G, this.x, N)
    var gx_str = BigInt.bigInt2str(this.gx, 10)

    var key = AES.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
    var iv = AES.enc.Hex.parse('0')
    var opts = { mode: AES.mode.CTR, iv: iv }

    send.encrypted = AES.AES.encrypt(gx_str, key, opts)
    send.hashed = SHA256.SHA256(gx_str)

    this.sendMsg(send, cb)

  },

  sendMsg: function (send, cb) {
    console.log('sending')
    cb(send, this.receiveMsg)
  },

  receiveMsg: function (msg, cb) {
    if (typeof cb !== 'function')
      throw new Error('Nowhere to go?')

    this.handleAKE(msg, cb)
  },

  error: function (err) {
    console.log(err)
  }

}