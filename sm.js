var CryptoJS = require('./vendor/sha256.js')
var BigInt = require('./vendor/bigint.js')


// helpers
function divMod(num, den, n) {
  return BigInt.multMod(num, BigInt.inverseMod(den, n), n)
}

function subMod(one, two, n) {
  one = BigInt.mod(one, n)
  two = BigInt.mod(two, n)
  if (BigInt.greater(two, one)) one = BigInt.add(one, n)
  return BigInt.sub(one, two)
}

function randomExponent() {
  return BigInt.randBigInt(1536)
}

function randomValue() {
  return BigInt.randBigInt(128)
}

function smpHash(version, fmpi, smpi) {
  var sha256 = CryptoJS.algo.SHA256.create()
  sha256.update(version.toString())
  sha256.update(BigInt.bigInt2str(fmpi, 10))
  if (smpi) sha256.update(BigInt.bigInt2str(smpi, 10))
  var hash = sha256.finalize()
  return BigInt.str2bigInt(hash.toString(CryptoJS.enc.Hex), 16)
}

function multPowMod(a, b, c, d, e) {
  return BigInt.multMod(BigInt.powMod(a, b, e), BigInt.powMod(c, d, e), e)
}

function ZKP(v, c, d, ga) {
  return BigInt.equals(c, smpHash(v, multPowMod(G, d, ga, c, N)))
}

// smp machine states
var SMPSTATE_EXPECT1 = 1
  , SMPSTATE_EXPECT2 = 2
  , SMPSTATE_EXPECT3 = 3
  , SMPSTATE_EXPECT4 = 4

// diffie-hellman modulus and generator
// see group 5, RFC 3526
var G = BigInt.str2bigInt('2', 10)
var N = BigInt.str2bigInt((
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
          + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
          + "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
          + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
          + "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
          + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
          + "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
          + "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
        ).replace(/\s+/g, ''), 16)

// to calculate D's for zero-knowledge proofs
var Q = BigInt.sub(N, BigInt.str2bigInt('1', 10))
BigInt.divInt_(Q, 2)  // meh

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

  // initialize vars
  this.init()

  // bind methods
  var self = this
  ;['sendMsg', 'receiveMsg'].forEach(function (meth) {
    self[meth] = self[meth].bind(self)
  })
}

SM.prototype = {

  // set the constructor
  // because the prototype is being replaced
  constructor: SM,

  // set the initial values
  // also used when aborting
  init: function () {
    this.a2 = null
    this.a3 = null

    this.g2a = null
    this.g3a = null

    this.g2 = null
    this.g3 = null

    this.p = null
    this.q = null
    this.r = null

    this.c2 = null
    this.c3 = null
    this.d2 = null
    this.d3 = null

    this.smpstate = SMPSTATE_EXPECT1
  },

  makeG2s: function () {
    this.g2a = BigInt.powMod(G, this.a2, N)
    this.g3a = BigInt.powMod(G, this.a3, N)
    return { g2a: this.g2a, g3a: this.g3a }
  },

  computeGs: function (msg) {
    this.g2 = BigInt.powMod(msg.g2a, this.a2, N)
    this.g3 = BigInt.powMod(msg.g3a, this.a3, N)
  },

  computePQ: function (r, send) {
    send.p = this.p = BigInt.powMod(this.g3, r, N)
    send.q = this.q = multPowMod(G, r, this.g2, this.secret, N)
  },

  computeR: function (msg, send, inv) {
    var q1 = inv ? msg.q : this.q
    var q2 = inv ? this.q : msg.q
    send.r = this.r = BigInt.powMod(divMod(q1, q2, N), this.a3, N)
  },

  computeRab: function (msg) {
    return BigInt.powMod(msg.r, this.a3, N)
  },

  computeC: function (v, r) {
    return smpHash(v, BigInt.powMod(G, r, N))
  },

  computeD: function (r, a, c) {
    return subMod(r, BigInt.multMod(a, c, Q), Q)
  },

  // the bulk of the work
  handleSM: function (msg, cb) {

    var send = {}
      , reply = true

    switch (this.smpstate) {

      case SMPSTATE_EXPECT1:

        // verify znp's
        console.log('Check c2: ' + ZKP(1, msg.c2, msg.d2, msg.g2a))
        console.log('Check c3: ' + ZKP(2, msg.c3, msg.d3, msg.g3a))

        this.a2 = randomExponent()
        this.a3 = randomExponent()

        send = this.makeG2s()

        // zero-knowledge proof that the exponents
        // associated with g2a & g3a are known
        var r2 = randomExponent()
        var r3 = randomExponent()
        send.c2 = this.c2 = this.computeC(3, r2)
        send.c3 = this.c3 = this.computeC(4, r3)
        send.d2 = this.d2 = this.computeD(r2, this.a2, this.c2)
        send.d3 = this.d3 = this.computeD(r3, this.a3, this.c3)

        this.computeGs(msg)

        var r4 = randomExponent()
        this.computePQ(r4, send)

        // zero-knowledge proof that P & Q
        // were generated according to the protocol
        var r5 = randomExponent()
        var r6 = randomExponent()
        var tmp = multPowMod(G, r5, this.g2, r6, N)
        send.cP = smpHash(5, BigInt.powMod(this.g3, r5, N), tmp)
        send.d5 = this.computeD(r5, r4, send.cP)
        send.d6 = this.computeD(r6, this.secret, send.cP)

        this.smpstate = SMPSTATE_EXPECT3
        send.type = 3
        break

      case SMPSTATE_EXPECT2:

        // verify znp of c3 / c3
        console.log('Check c2: ' + ZKP(3, msg.c2, msg.d2, msg.g2a))
        console.log('Check c3: ' + ZKP(4, msg.c3, msg.d3, msg.g3a))

        this.computeGs(msg)

        // verify znp of cP
        var t1 = multPowMod(this.g3, msg.d5, msg.p, msg.cP, N)
        var t2 = multPowMod(G, msg.d5, this.g2, msg.d6, N)
        t2 = BigInt.multMod(t2, BigInt.powMod(msg.q, msg.cP, N), N)
        var cP = smpHash(5, t1, t2)
        console.log('Check cP: ' + BigInt.equals(msg.cP, cP))

        var r4 = randomExponent()
        this.computePQ(r4, send)

        // zero-knowledge proof that P & Q
        // were generated according to the protocol
        var r5 = randomExponent()
        var r6 = randomExponent()
        var tmp = multPowMod(G, r5, this.g2, r6, N)
        send.cP = smpHash(6, BigInt.powMod(this.g3, r5, N), tmp)
        send.d5 = this.computeD(r5, r4, send.cP)
        send.d6 = this.computeD(r6, this.secret, send.cP)

        this.computeR(msg, send)

        // zero-knowledge proof that R
        // was generated according to the protocol
        var r7 = randomExponent()
        var tmp2 = BigInt.powMod(divMod(this.q, msg.q, N), r7, N)
        send.cR = smpHash(7, BigInt.powMod(G, r7, N), tmp2)
        send.d7 = this.computeD(r7, this.a3, send.cR)

        send.g3a = this.g3a  // redundant

        this.smpstate = SMPSTATE_EXPECT4
        send.type = 4
        break

      case SMPSTATE_EXPECT3:

        // verify znp of cP
        var t1 = multPowMod(this.g3, msg.d5, msg.p, msg.cP, N)
        var t2 = multPowMod(G, msg.d5, this.g2, msg.d6, N)
        t2 = BigInt.multMod(t2, BigInt.powMod(msg.q, msg.cP, N), N)
        var cP = smpHash(6, t1, t2)
        console.log('Check cP: ' + BigInt.equals(msg.cP, cP))

        // verify znp of cR
        var t3 = multPowMod(G, msg.d7, msg.g3a, msg.cR, N)
        this.QoQ = divMod(msg.q, this.q, N)  // save Q over Q
        var t4 = multPowMod(this.QoQ, msg.d7, msg.r, msg.cR, N)
        var cR = smpHash(7, t3, t4)
        console.log('Check cR: ' + BigInt.equals(msg.cR, cR))

        this.computeR(msg, send, true)

        // zero-knowledge proof that R
        // was generated according to the protocol
        var r7 = randomExponent()
        var tmp2 = BigInt.powMod(this.QoQ, r7, N)
        send.cR = smpHash(8, BigInt.powMod(G, r7, N), tmp2)
        send.d7 = this.computeD(r7, this.a3, send.cR)

        var rab = this.computeRab(msg)
        console.log('Compare Rab: '
          + BigInt.equals(rab, divMod(msg.p, this.p, N)))

        send.p = this.p  // redundant
        send.q = this.q  // redundant
        send.g3a = this.g3a  // redundant

        send.type = 5
        this.init()
        break

      case SMPSTATE_EXPECT4:

        // verify znp of cR
        var t3 = multPowMod(G, msg.d7, msg.g3a, msg.cR, N)
        var t4 = multPowMod(divMod(this.q, msg.q, N), msg.d7, msg.r, msg.cR, N)
        var cR = smpHash(8, t3, t4)
        console.log('Check cR: ' + BigInt.equals(msg.cR, cR))

        var rab = this.computeRab(msg)
        console.log('Compare Rab: '
          + BigInt.equals(rab, divMod(this.p, msg.p, N)))

        this.init()
        reply = false
        break

      default:
        this.error('Unrecognized state.', cb)

    }

    if (reply) this.sendMsg(send, cb)

  },

  // send a message
  sendMsg: function (send, cb) {

    // "?OTR:" + base64encode(msg) + "."
    console.log('sending')

    cb(send, this.receiveMsg)
  },

  // receive a message
  receiveMsg: function (msg, cb) {

    if (typeof cb !== 'function')
      throw new Error('Nowhere to go?')

    if (typeof msg !== 'object')
      return this.error('No message type.', cb)

    var expectStates = {
        2: SMPSTATE_EXPECT1
      , 3: SMPSTATE_EXPECT2
      , 4: SMPSTATE_EXPECT3
      , 5: SMPSTATE_EXPECT4
    }

    switch (msg.type) {

      case 2:  // these fall through
      case 3:
      case 4:
      case 5:
        if (this.smpstate !== expectStates[msg.type])
          return this.error('Unexpected state.', cb)
        this.handleSM(msg, cb)
        break

      // abort! there was an error
      case 6:
        this.init()
        break

      default:
        this.error('Invalid message type.', cb)

    }

  },

  error: function (err, cb) {
    console.log(err)
    this.init()
    this.sendMsg({ type: 6 }, cb)
  },

  initiate: function (cb) {
    if (typeof cb !== 'function')
      throw new Error('Nowhere to go?')

    // start over
    if (this.smpstate !== SMPSTATE_EXPECT1) this.error()

    this.a2 = randomValue()
    this.a3 = randomValue()

    var send = this.makeG2s()

    // zero-knowledge proof that the exponents
    // associated with g2a & g3a are known
    var r2 = randomValue()
    var r3 = randomValue()
    send.c2 = this.c2 = this.computeC(1, r2)
    send.c3 = this.c3 = this.computeC(2, r3)
    send.d2 = this.d2 = this.computeD(r2, this.a2, this.c2)
    send.d3 = this.d3 = this.computeD(r3, this.a3, this.c3)

    // set the next expected state
    this.smpstate = SMPSTATE_EXPECT2

    // set the message type
    send.type = 2

    this.sendMsg(send, cb)
  }

}