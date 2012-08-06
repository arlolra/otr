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
    , DSA = root.DSA

  if (typeof require !== 'undefined') {
    BigInt || (BigInt = require('./vendor/bigint.js'))
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    DH || (DH = require('./dh.json'))
    HLP || (HLP = require('./helpers.js'))
    DSA || (DSA = require('./dsa.js'))
  }

  // smp machine states
  var SMPSTATE_EXPECT1 = 1
    , SMPSTATE_EXPECT2 = 2
    , SMPSTATE_EXPECT3 = 3
    , SMPSTATE_EXPECT4 = 4

  // otr message states
  var MSGSTATE_PLAINTEXT = 0
    , MSGSTATE_ENCRYPTED = 1
    , MSGSTATE_FINISHED = 2

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)

  // to calculate D's for zero-knowledge proofs
  var Q = BigInt.sub(N, BigInt.str2bigInt('1', 10))
  BigInt.divInt_(Q, 2)  // meh

  function SM(otr) {
    if (!(this instanceof SM)) return new SM(otr)

    this.otr = otr
    this.version = '1'
    this.our_fp = DSA.fingerprint(otr.priv)
    this.their_fp = DSA.fingerprint(otr.their_priv_pk)

    // initial state
    this.init()
  }

  SM.prototype = {

    // set the constructor
    // because the prototype is being replaced
    constructor: SM,

    // set the initial values
    // also used when aborting
    init: function () {
      this.smpstate = SMPSTATE_EXPECT1
      this.secret = null
    },

    makeSecret: function (our) {
      var sha256 = CryptoJS.algo.SHA256.create()
      sha256.update(this.version)
      sha256.update(our ? this.our_fp : this.their_fp)
      sha256.update(our ? this.their_fp : this.our_fp)
      sha256.update(this.otr.ssid)    // secure session id
      sha256.update(this.otr.secret)  // user input string
      var hash = sha256.finalize()
      this.secret = BigInt.str2bigInt(hash.toString(CryptoJS.enc.Hex), 16)
    },

    makeG2s: function () {
      this.g2a = BigInt.powMod(G, this.a2, N)
      this.g3a = BigInt.powMod(G, this.a3, N)
    },

    computeGs: function (g2a, g3a) {
      this.g2 = BigInt.powMod(g2a, this.a2, N)
      this.g3 = BigInt.powMod(g3a, this.a3, N)
    },

    computePQ: function (r) {
      this.p = BigInt.powMod(this.g3, r, N)
      this.q = HLP.multPowMod(G, r, this.g2, this.secret, N)
    },

    computeR: function () {
      this.r = BigInt.powMod(this.QoQ, this.a3, N)
    },

    computeRab: function (r) {
      return BigInt.powMod(r, this.a3, N)
    },

    computeC: function (v, r) {
      return HLP.smpHash(v, BigInt.powMod(G, r, N))
    },

    computeD: function (r, a, c) {
      return HLP.subMod(r, BigInt.multMod(a, c, Q), Q)
    },

    // the bulk of the work
    handleSM: function (msg) {
      var send, r2, r3, r4, r5, r6, r7, t1, t2, t3, t4
        , rab, tmp, tmp2, cP, cR, d5, d6, d7, ms

      var expectStates = {
          2: SMPSTATE_EXPECT1
        , 3: SMPSTATE_EXPECT2
        , 4: SMPSTATE_EXPECT3
        , 5: SMPSTATE_EXPECT4
      }

      if (msg.type === 6) {
        this.init()
        return
      }

      // abort! there was an error
      if ( this.smpstate !== expectStates[msg.type] ||
           this.otr.msgstate !== MSGSTATE_ENCRYPTED
      ) return this.abort()

      switch (this.smpstate) {

        case SMPSTATE_EXPECT1:
          // 0:g2a, 1:c2, 2:d2, 3:g3a, 4:c3, 5:d3
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 6) return this.abort()
          msg = HLP.unpackMPIs(6, msg.msg.substring(4))

          this.makeSecret()

          // verify znp's
          if (!HLP.ZKP(1, msg[1], HLP.multPowMod(G, msg[2], msg[0], msg[1], N)))
            return this.abort()

          if (!HLP.ZKP(2, msg[4], HLP.multPowMod(G, msg[5], msg[3], msg[4], N)))
            return this.abort()

          this.g3ao = msg[3]  // save for later

          this.a2 = HLP.randomExponent()
          this.a3 = HLP.randomExponent()

          this.makeG2s()

          // zero-knowledge proof that the exponents
          // associated with g2a & g3a are known
          r2 = HLP.randomExponent()
          r3 = HLP.randomExponent()
          this.c2 = this.computeC(3, r2)
          this.c3 = this.computeC(4, r3)
          this.d2 = this.computeD(r2, this.a2, this.c2)
          this.d3 = this.computeD(r3, this.a3, this.c3)

          this.computeGs(msg[0], msg[3])

          r4 = HLP.randomExponent()

          this.computePQ(r4)

          // zero-knowledge proof that P & Q
          // were generated according to the protocol
          r5 = HLP.randomExponent()
          r6 = HLP.randomExponent()
          tmp = HLP.multPowMod(G, r5, this.g2, r6, N)
          cP = HLP.smpHash(5, BigInt.powMod(this.g3, r5, N), tmp)
          d5 = this.computeD(r5, r4, cP)
          d6 = this.computeD(r6, this.secret, cP)

          this.smpstate = SMPSTATE_EXPECT3

          send = HLP.packINT(11) + HLP.packMPIs([
              this.g2a
            , this.c2
            , this.d2
            , this.g3a
            , this.c3
            , this.d3
            , this.p
            , this.q
            , cP
            , d5
            , d6
          ])

          // TLV
          send = HLP.packTLV(3, send)
          break

        case SMPSTATE_EXPECT2:
          // 0:g2a, 1:c2, 2:d2, 3:g3a, 4:c3, 5:d3, 6:p, 7:q, 8:cP, 9:d5, 10:d6
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 11) return this.abort()
          msg = HLP.unpackMPIs(11, msg.msg.substring(4))

          // verify znp of c3 / c3
          if (!HLP.ZKP(3, msg[1], HLP.multPowMod(G, msg[2], msg[0], msg[1], N)))
            return this.abort()

          if (!HLP.ZKP(4, msg[4], HLP.multPowMod(G, msg[5], msg[3], msg[4], N)))
            return this.abort()

          this.g3ao = msg[3]  // save for later

          this.computeGs(msg[0], msg[3])

          // verify znp of cP
          t1 = HLP.multPowMod(this.g3, msg[9], msg[6], msg[8], N)
          t2 = HLP.multPowMod(G, msg[9], this.g2, msg[10], N)
          t2 = BigInt.multMod(t2, BigInt.powMod(msg[7], msg[8], N), N)

          if (!HLP.ZKP(5, msg[8], t1, t2))
            return this.abort()

          r4 = HLP.randomExponent()

          this.computePQ(r4)

          // zero-knowledge proof that P & Q
          // were generated according to the protocol
          r5 = HLP.randomExponent()
          r6 = HLP.randomExponent()
          tmp = HLP.multPowMod(G, r5, this.g2, r6, N)
          cP = HLP.smpHash(6, BigInt.powMod(this.g3, r5, N), tmp)
          d5 = this.computeD(r5, r4, cP)
          d6 = this.computeD(r6, this.secret, cP)

          // store these
          this.QoQ = HLP.divMod(this.q, msg[7], N)
          this.PoP = HLP.divMod(this.p, msg[6], N)

          this.computeR()

          // zero-knowledge proof that R
          // was generated according to the protocol
          r7 = HLP.randomExponent()
          tmp2 = BigInt.powMod(this.QoQ, r7, N)
          cR = HLP.smpHash(7, BigInt.powMod(G, r7, N), tmp2)
          d7 = this.computeD(r7, this.a3, cR)

          this.smpstate = SMPSTATE_EXPECT4

          send = HLP.packINT(8) + HLP.packMPIs([
              this.p
            , this.q
            , cP
            , d5
            , d6
            , this.r
            , cR
            , d7
          ])

          // TLV
          send = HLP.packTLV(4, send)
          break

        case SMPSTATE_EXPECT3:
          // 0:p, 1:q, 2:cP, 3:d5, 4:d6, 5:r, 6:cR, 7:d7
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 8) return this.abort()
          msg = HLP.unpackMPIs(8, msg.msg.substring(4))

          // verify znp of cP
          t1 = HLP.multPowMod(this.g3, msg[3], msg[0], msg[2], N)
          t2 = HLP.multPowMod(G, msg[3], this.g2, msg[4], N)
          t2 = BigInt.multMod(t2, BigInt.powMod(msg[1], msg[2], N), N)

          if (!HLP.ZKP(6, msg[2], t1, t2))
            return this.abort()

          // verify znp of cR
          t3 = HLP.multPowMod(G, msg[7], this.g3ao, msg[6], N)
          this.QoQ = HLP.divMod(msg[1], this.q, N)  // save Q over Q
          t4 = HLP.multPowMod(this.QoQ, msg[7], msg[5], msg[6], N)

          if (!HLP.ZKP(7, msg[6], t3, t4))
            return this.abort()

          this.computeR()

          // zero-knowledge proof that R
          // was generated according to the protocol
          r7 = HLP.randomExponent()
          tmp2 = BigInt.powMod(this.QoQ, r7, N)
          cR = HLP.smpHash(8, BigInt.powMod(G, r7, N), tmp2)
          d7 = this.computeD(r7, this.a3, cR)

          rab = this.computeRab(msg[5])

          if (!BigInt.equals(rab, HLP.divMod(msg[0], this.p, N)))
            return this.abort()

          send = HLP.packINT(3) + HLP.packMPIs([ this.r, cR, d7 ])

          // TLV
          send = HLP.packTLV(5, send)

          this.otr.trust = true
          this.init()
          break

        case SMPSTATE_EXPECT4:
          // 0:r, 1:cR, 2:d7
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 3) return this.abort()
          msg = HLP.unpackMPIs(3, msg.msg.substring(4))

          // verify znp of cR
          t3 = HLP.multPowMod(G, msg[2], this.g3ao, msg[1], N)
          t4 = HLP.multPowMod(this.QoQ, msg[2], msg[0], msg[1], N)
          if (!HLP.ZKP(8, msg[1], t3, t4))
            return this.abort()

          rab = this.computeRab(msg[0])

          if (!BigInt.equals(rab, this.PoP))
            return this.abort()

          this.otr.trust = true
          this.init()
          return

      }

      this.sendMsg(send)
    },

    // send a message
    sendMsg: function (send) {
      this.otr.sendMsg('\x00' + send)
    },

    initiate: function () {

      if (this.otr.msgstate !== MSGSTATE_ENCRYPTED)
        return this.otr.error('Not ready to send encrypted messages.')

      this.makeSecret(true)

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

      var send = HLP.packINT(6) + HLP.packMPIs([
          this.g2a
        , this.c2
        , this.d2
        , this.g3a
        , this.c3
        , this.d3
      ])

      // TLV
      send = HLP.packTLV(2, send)

      this.sendMsg(send)
    },

    abort: function () {
      this.init()
      this.sendMsg(HLP.packTLV(6, ''))
    }

  }

}).call(this)