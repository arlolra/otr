var CryptoJS = require('./vendor/sha256.js')
var BigInt = require('./vendor/bigint.js')


// helpers
function divMod(num, den, n) {
  return BigInt.multMod(num, BigInt.inverseMod(den, n), n)
} 

// smp state machine states
var SMPSTATE_EXPECT1 = 1
  , SMPSTATE_EXPECT2 = 2
  , SMPSTATE_EXPECT3 = 3
  , SMPSTATE_EXPECT4 = 4

// diffie-hellman modulus and generator
// see group 5, RFC 3526
var g = BigInt.str2bigInt('2', 10)
var n = BigInt.str2bigInt((
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
          + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
          + "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
          + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
          + "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
          + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
          + "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
          + "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
        ).replace(/\s+/g, ''), 16)

// to calculate D's 
var q = divMod(
    BigInt.sub(n, BigInt.str2bigInt('1', 10))
  , BigInt.str2bigInt('2', 10)
  , n
)

module.exports = SM

function SM(secret) {
  if (!(this instanceof SM)) return new SM(secret)

  var sha256 = CryptoJS.algo.SHA256.create()
  sha256.update('1')      // version of smp
  sha256.update('123')    // initiator fingerprint
  sha256.update('456')    // responder fingerprint
  sha256.update('ssid')   // secure session id
  sha256.update(secret)   // user input string
  var hash = sha256.finalize()
  this.secret = BigInt.str2bigInt(hash.toString(CryptoJS.enc.Hex), 16)
  
  this.a2 = null
  this.a3 = null

  this.g2 = null
  this.g3 = null

  this.P = null
  this.Q = null
  this.R = null

  this.received_question = false
  this.nextExpected = SMPSTATE_EXPECT1
  
  this.init()

}

SM.prototype = {

  // set the constructor
  // because the prototype is being replaced
  constructor: SM,

  // set the initial values
  // also used when aborting
  init: function () {
    this.a2 = this.randomExponent()
    this.a3 = this.randomExponent()
  },

  // just returns a random exponent
  randomExponent: function () {
    return BigInt.randBigInt(1536)
  },
  
  makeG2s: function () {
    return {
        g2a: BigInt.powMod(g, this.a2, n)
      , g3a: BigInt.powMod(g, this.a3, n)
    }
  },
  
  computeGs: function (msg) {
    this.g2 = BigInt.powMod(msg.g2a, this.a2, n)
    this.g3 = BigInt.powMod(msg.g3a, this.a3, n)
  },
  
  computePQ: function (send) {
    var r = this.randomExponent()
    send.P = this.P = BigInt.powMod(this.g3, r, n)
    
    var g1r = BigInt.powMod(g, r, n)
    var g2x = BigInt.powMod(this.g2, this.secret, n)
    send.Q = this.Q = BigInt.multMod(g1r, g2x, n)
  },
  
  computeR: function (msg, send, inv) {
    var q1 = inv ? msg.Q : this.Q
    var q2 = inv ? this.Q : msg.Q
    send.R = this.R = BigInt.powMod(divMod(q1, q2, n), this.a3, n)
  },
  
  computeRab: function (msg) {
    return BigInt.powMod(msg.R, this.a3, n)
  },

  // the bulk of the work
  handleSM: function (msg, rcv) {

    var send = {}
      , reply = true

    switch (this.nextExpected) {

      // Bob
      case SMPSTATE_EXPECT1:
        send = this.makeG2s()
        this.computeGs(msg)
        this.computePQ(send)
        this.nextExpected = SMPSTATE_EXPECT3
        break
      
      // Alice
      case SMPSTATE_EXPECT2:
        this.computeGs(msg)
        this.computePQ(send)
        this.computeR(msg, send)
        this.nextExpected = SMPSTATE_EXPECT4
        break

      // Bob
      case SMPSTATE_EXPECT3:
        send.P = this.P  // redundant
        this.computeR(msg, send, true)
        var Rab = this.computeRab(msg)
        console.log('Compare Rab: '
          + BigInt.equals(Rab, divMod(msg.P, this.P, n)))
        this.nextExpected = SMPSTATE_EXPECT1
        break
      
      // Alice
      case SMPSTATE_EXPECT4:
        var Rab = this.computeRab(msg)
        console.log('Compare Rab: '
          + BigInt.equals(Rab, divMod(this.P, msg.P, n)))
        this.nextExpected = SMPSTATE_EXPECT1
        reply = false
        break

      default:
        throw new Error('dang')

    }

    if (reply) this.sendMsg(send, rcv)

  },

  smpHash: function (version, fmpi, smpi) {
    var sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(version.toString())
    sha256.update(BigInt.bigInt2str(fmpi, 10))
    if (smpi) sha256.update(BigInt.bigInt2str(smpi, 10))
    var hash = sha256.finalize()
    return BigInt.str2bigInt(hash.toString(CryptoJS.enc.Hex), 16)
  },

  ZKP: function (v, c, D, ga) {
    return BigInt.equals(c,
      this.smpHash(v,
        BigInt.multMod(
          BigInt.powMod(g, D, n),
          BigInt.powMod(ga, c, n),
        n)
      )
    )
  },

  computeC: function (v, r) {
    return this.smpHash(v, BigInt.powMod(g, r, n))
  },

  computeD: function (r, a, c) {
    return BigInt.sub(r, BigInt.multMod(a, c, q))
  },

  // send a message
  sendMsg: function (msg, rcv) {
    
    // "?OTR:" + base64encode(msg) + "."
    console.log('sending')
    
    // Alice
    if (!msg) {
      this.nextExpected = SMPSTATE_EXPECT2
      var send = this.makeG2s()

      var r2 = this.randomExponent()
      var r3 = this.randomExponent()

      var c2 = this.computeC(1, r2)
      var c3 = this.computeC(2, r3)

      var D2 = this.computeD(r2, this.a2, c2)
      var D3 = this.computeD(r3, this.a3, c3)

      console.log('Check c2: ' + this.ZKP(1, c2, D2, send.g2a))
      console.log('Check c3: ' + this.ZKP(2, c3, D3, send.g3a))

      return rcv.receiveMsg(send, this)
    }
    rcv.receiveMsg(msg, this)
  },

  // receive a message
  receiveMsg: function (msg, rcv) {
    this.handleSM(msg, rcv)
  }

}