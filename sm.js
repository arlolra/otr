;(function () {

  var root = this

  if (typeof exports !== 'undefined') {
    module.exports = SM
  } else {
    root.SM = SM
  }

  var BigInt = root.BigInt
    , CryptoJS = root.CryptoJS
    , DH = root.DH
    , HLP = root.HLP

  if (typeof require !== 'undefined') {
    BigInt || (BigInt = require('./vendor/bigint.js'))
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    DH || (DH = require('./dh.json'))
    HLP || (HLP = require('./helpers.js'))
  }

  // smp machine states
  var SMPSTATE_EXPECT1 = 1
    , SMPSTATE_EXPECT2 = 2
    , SMPSTATE_EXPECT3 = 3
    , SMPSTATE_EXPECT4 = 4

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)

  // to calculate D's for zero-knowledge proofs
  var Q = BigInt.sub(N, BigInt.str2bigInt('1', 10))
  BigInt.divInt_(Q, 2)  // meh

  function SM(secret, ssid, ifp, rfp) {
    if (!(this instanceof SM)) return new SM(secret, ssid, ifp, rfp)

    var sha256 = CryptoJS.algo.SHA256.create()
    sha256.update('1')     // version of smp
    sha256.update(ifp)     // initiator fingerprint
    sha256.update(rfp)     // responder fingerprint
    sha256.update(ssid)    // secure session id
    sha256.update(secret)  // user input string
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
      this.smpstate = SMPSTATE_EXPECT1
    },

    makeG2s: function () {
      this.g2a = BigInt.powMod(G, this.a2, N)
      this.g3a = BigInt.powMod(G, this.a3, N)
    },

    computeGs: function (msg) {
      this.g2 = BigInt.powMod(msg.g2a, this.a2, N)
      this.g3 = BigInt.powMod(msg.g3a, this.a3, N)
    },

    computePQ: function (r, send) {
      send.p = this.p = BigInt.powMod(this.g3, r, N)
      send.q = this.q = HLP.multPowMod(G, r, this.g2, this.secret, N)
    },

    computeR: function (send) {
      send.r = this.r = BigInt.powMod(this.QoQ, this.a3, N)
    },

    computeRab: function (msg) {
      return BigInt.powMod(msg.r, this.a3, N)
    },

    computeC: function (v, r) {
      return HLP.smpHash(v, BigInt.powMod(G, r, N))
    },

    computeD: function (r, a, c) {
      return HLP.subMod(r, BigInt.multMod(a, c, Q), Q)
    },

    // the bulk of the work
    handleSM: function (msg, cb) {
      var r2, r3, r4, r5, r6, r7, t1, t2, t3, t4, rab, tmp, tmp2

      var send = {}
        , reply = true

      switch (this.smpstate) {

        case SMPSTATE_EXPECT1:

          // verify znp's
          console.log('Check c2: ' +
            HLP.ZKP(1, msg.c2, HLP.multPowMod(G, msg.d2, msg.g2a, msg.c2, N)))
          console.log('Check c3: ' +
            HLP.ZKP(2, msg.c3, HLP.multPowMod(G, msg.d3, msg.g3a, msg.c3, N)))

          this.g3ao = msg.g3a  // save for later

          this.a2 = HLP.randomExponent()
          this.a3 = HLP.randomExponent()

          send = this.makeG2s()

          // zero-knowledge proof that the exponents
          // associated with g2a & g3a are known
          r2 = HLP.randomExponent()
          r3 = HLP.randomExponent()
          send.c2 = this.c2 = this.computeC(3, r2)
          send.c3 = this.c3 = this.computeC(4, r3)
          send.d2 = this.d2 = this.computeD(r2, this.a2, this.c2)
          send.d3 = this.d3 = this.computeD(r3, this.a3, this.c3)

          this.computeGs(msg)

          r4 = HLP.randomExponent()
          this.computePQ(r4, send)

          // zero-knowledge proof that P & Q
          // were generated according to the protocol
          r5 = HLP.randomExponent()
          r6 = HLP.randomExponent()
          tmp = HLP.multPowMod(G, r5, this.g2, r6, N)
          send.cP = HLP.smpHash(5, BigInt.powMod(this.g3, r5, N), tmp)
          send.d5 = this.computeD(r5, r4, send.cP)
          send.d6 = this.computeD(r6, this.secret, send.cP)

          this.smpstate = SMPSTATE_EXPECT3
          send.type = 3
          break

        case SMPSTATE_EXPECT2:

          // verify znp of c3 / c3
          console.log('Check c2: ' +
            HLP.ZKP(3, msg.c2, HLP.multPowMod(G, msg.d2, msg.g2a, msg.c2, N)))
          console.log('Check c3: ' +
            HLP.ZKP(4, msg.c3, HLP.multPowMod(G, msg.d3, msg.g3a, msg.c3, N)))

          this.g3ao = msg.g3a  // save for later

          this.computeGs(msg)

          // verify znp of cP
          t1 = HLP.multPowMod(this.g3, msg.d5, msg.p, msg.cP, N)
          t2 = HLP.multPowMod(G, msg.d5, this.g2, msg.d6, N)
          t2 = BigInt.multMod(t2, BigInt.powMod(msg.q, msg.cP, N), N)
          console.log('Check cP: ' + HLP.ZKP(5, msg.cP, t1, t2))

          r4 = HLP.randomExponent()
          this.computePQ(r4, send)

          // zero-knowledge proof that P & Q
          // were generated according to the protocol
          r5 = HLP.randomExponent()
          r6 = HLP.randomExponent()
          tmp = HLP.multPowMod(G, r5, this.g2, r6, N)
          send.cP = HLP.smpHash(6, BigInt.powMod(this.g3, r5, N), tmp)
          send.d5 = this.computeD(r5, r4, send.cP)
          send.d6 = this.computeD(r6, this.secret, send.cP)

          // store these
          this.QoQ = HLP.divMod(this.q, msg.q, N)
          this.PoP = HLP.divMod(this.p, msg.p, N)

          this.computeR(send)

          // zero-knowledge proof that R
          // was generated according to the protocol
          r7 = HLP.randomExponent()
          tmp2 = BigInt.powMod(this.QoQ, r7, N)
          send.cR = HLP.smpHash(7, BigInt.powMod(G, r7, N), tmp2)
          send.d7 = this.computeD(r7, this.a3, send.cR)

          this.smpstate = SMPSTATE_EXPECT4
          send.type = 4
          break

        case SMPSTATE_EXPECT3:

          // verify znp of cP
          t1 = HLP.multPowMod(this.g3, msg.d5, msg.p, msg.cP, N)
          t2 = HLP.multPowMod(G, msg.d5, this.g2, msg.d6, N)
          t2 = BigInt.multMod(t2, BigInt.powMod(msg.q, msg.cP, N), N)
          console.log('Check cP: ' + HLP.ZKP(6, msg.cP, t1, t2))

          // verify znp of cR
          t3 = HLP.multPowMod(G, msg.d7, this.g3ao, msg.cR, N)
          this.QoQ = HLP.divMod(msg.q, this.q, N)  // save Q over Q
          t4 = HLP.multPowMod(this.QoQ, msg.d7, msg.r, msg.cR, N)
          console.log('Check cR: ' + HLP.ZKP(7, msg.cR, t3, t4))

          this.computeR(send)

          // zero-knowledge proof that R
          // was generated according to the protocol
          r7 = HLP.randomExponent()
          tmp2 = BigInt.powMod(this.QoQ, r7, N)
          send.cR = HLP.smpHash(8, BigInt.powMod(G, r7, N), tmp2)
          send.d7 = this.computeD(r7, this.a3, send.cR)

          rab = this.computeRab(msg)
          console.log('Compare Rab: ' +
            BigInt.equals(rab, HLP.divMod(msg.p, this.p, N)))

          send.type = 5
          this.init()
          break

        case SMPSTATE_EXPECT4:

          // verify znp of cR
          t3 = HLP.multPowMod(G, msg.d7, this.g3ao, msg.cR, N)
          t4 = HLP.multPowMod(this.QoQ, msg.d7, msg.r, msg.cR, N)
          console.log('Check cR: ' + HLP.ZKP(8, msg.cR, t3, t4))

          rab = this.computeRab(msg)
          console.log('Compare Rab: ' + BigInt.equals(rab, this.PoP))

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

    initiate: function () {
      if (this.smpstate !== SMPSTATE_EXPECT1)
        this.abort()  // abort + restart

      this.a2 = HLP.randomValue()
      this.a3 = HLP.randomValue()
      this.makeG2s()

      // zero-knowledge proof that the exponents
      // associated with g2a & g3a are known
      var r2 = HLP.randomValue()
      var r3 = HLP.randomValue()
      this.c2 = this.computeC(1, r2)
      this.c3 = this.computeC(2, r3)
      this.d2 = this.computeD(r2, this.a2, this.c2)
      this.d3 = this.computeD(r3, this.a3, this.c3)

      // set the next expected state
      this.smpstate = SMPSTATE_EXPECT2

      var send = 2  // set the message type
      send += HLP.packMPI(this.g2a)
      send += HLP.packMPI(this.c2)
      send += HLP.packMPI(this.d2)
      send += HLP.packMPI(this.g2a)
      send += HLP.packMPI(this.c3)
      send += HLP.packMPI(this.d3)

      this.sendMsg(send)
    },

    abort: function () {
      this.init()
      this.sendMsg('6')
    }

  }

}).call(this)