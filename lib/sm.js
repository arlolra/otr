;(function () {

  var root = this

  var CryptoJS, BigInt, CONST, HLP, DSA
  if (typeof exports !== 'undefined') {
    module.exports = SM
    CryptoJS = require('../vendor/crypto.js')
    BigInt = require('../vendor/bigint.js')
    CONST = require('./const.js')
    HLP = require('./helpers.js')
    DSA = require('./dsa.js')
  } else {
    root.OTR.SM = SM
    CryptoJS = root.CryptoJS
    BigInt = root.BigInt
    CONST = root.OTR.CONST
    HLP = root.OTR.HLP
    DSA = root.DSA
  }

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(CONST.G, 10)
  var N = BigInt.str2bigInt(CONST.N, 16)

  // to calculate D's for zero-knowledge proofs
  var Q = BigInt.sub(N, BigInt.str2bigInt('1', 10))
  BigInt.divInt_(Q, 2)  // meh

  function SM(otr) {
    if (!(this instanceof SM)) return new SM(otr)

    this.otr = otr
    this.version = '1'
    this.our_fp = otr.priv.fingerprint()
    this.their_fp = otr.their_priv_pk.fingerprint()

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
      this.smpstate = CONST.SMPSTATE_EXPECT1
      this.secret = null
    },

    makeSecret: function (our, secret) {
      var sha256 = CryptoJS.algo.SHA256.create()
      sha256.update(CryptoJS.enc.Latin1.parse(HLP.packBytes(this.version, 1)))
      sha256.update(CryptoJS.enc.Hex.parse(our ? this.our_fp : this.their_fp))
      sha256.update(CryptoJS.enc.Hex.parse(our ? this.their_fp : this.our_fp))
      sha256.update(CryptoJS.enc.Latin1.parse(this.otr.ssid))
      sha256.update(CryptoJS.enc.Latin1.parse(secret))  // utf8?
      var hash = sha256.finalize()
      this.secret = HLP.bits2bigInt(hash.toString(CryptoJS.enc.Latin1))
    },

    makeG2s: function () {
      this.a2 = HLP.randomExponent()
      this.a3 = HLP.randomExponent()
      this.g2a = BigInt.powMod(G, this.a2, N)
      this.g3a = BigInt.powMod(G, this.a3, N)
      if ( !HLP.checkGroup(this.g2a, N) ||
           !HLP.checkGroup(this.g3a, N)
      ) this.makeG2s()
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
      var send, r2, r3, r7, t1, t2, t3, t4, rab, tmp2, cR, d7, ms

      var expectStates = {
          2: CONST.SMPSTATE_EXPECT1
        , 3: CONST.SMPSTATE_EXPECT2
        , 4: CONST.SMPSTATE_EXPECT3
        , 5: CONST.SMPSTATE_EXPECT4
        , 7: CONST.SMPSTATE_EXPECT1
      }

      if (msg.type === 6) {
        this.otr.trust = false
        this.init()
        this.otr._smcb('trust', this.otr.trust)
        return
      }

      // abort! there was an error
      if ( this.smpstate !== expectStates[msg.type] ||
           this.otr.msgstate !== CONST.MSGSTATE_ENCRYPTED
      ) return this.abort()

      switch (this.smpstate) {

        case CONST.SMPSTATE_EXPECT1:
          HLP.debug.call(this.otr, 'smp tlv 2')

          // user specified question
          var ind, question
          if (msg.type === 7) {
            ind = msg.msg.indexOf('\x00')
            question = msg.msg.substring(0, ind)
            msg.msg = msg.msg.substring(ind + 1)
          }

          // 0:g2a, 1:c2, 2:d2, 3:g3a, 4:c3, 5:d3
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 6) return this.abort()
          msg = HLP.unpackMPIs(6, msg.msg.substring(4))

          if ( !HLP.checkGroup(msg[0], N) ||
               !HLP.checkGroup(msg[3], N)
          ) return this.abort()

          // verify znp's
          if (!HLP.ZKP(1, msg[1], HLP.multPowMod(G, msg[2], msg[0], msg[1], N)))
            return this.abort()

          if (!HLP.ZKP(2, msg[4], HLP.multPowMod(G, msg[5], msg[3], msg[4], N)))
            return this.abort()

          this.g3ao = msg[3]  // save for later

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

          this.smpstate = CONST.SMPSTATE_EXPECT0

          // invoke question
          this.otr._smcb('question', question)
          return

        case CONST.SMPSTATE_EXPECT2:
          HLP.debug.call(this.otr, 'smp tlv 3')

          // 0:g2a, 1:c2, 2:d2, 3:g3a, 4:c3, 5:d3, 6:p, 7:q, 8:cP, 9:d5, 10:d6
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 11) return this.abort()
          msg = HLP.unpackMPIs(11, msg.msg.substring(4))

          if ( !HLP.checkGroup(msg[0], N) ||
               !HLP.checkGroup(msg[3], N) ||
               !HLP.checkGroup(msg[6], N) ||
               !HLP.checkGroup(msg[7], N)
          ) return this.abort()

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

          var r4 = HLP.randomExponent()
          this.computePQ(r4)

          // zero-knowledge proof that P & Q
          // were generated according to the protocol
          var r5 = HLP.randomExponent()
          var r6 = HLP.randomExponent()
          var tmp = HLP.multPowMod(G, r5, this.g2, r6, N)
          var cP = HLP.smpHash(6, BigInt.powMod(this.g3, r5, N), tmp)
          var d5 = this.computeD(r5, r4, cP)
          var d6 = this.computeD(r6, this.secret, cP)

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

          this.smpstate = CONST.SMPSTATE_EXPECT4

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

        case CONST.SMPSTATE_EXPECT3:
          HLP.debug.call(this.otr, 'smp tlv 4')

          // 0:p, 1:q, 2:cP, 3:d5, 4:d6, 5:r, 6:cR, 7:d7
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 8) return this.abort()
          msg = HLP.unpackMPIs(8, msg.msg.substring(4))

          if ( !HLP.checkGroup(msg[0], N) ||
               !HLP.checkGroup(msg[1], N) ||
               !HLP.checkGroup(msg[5], N)
          ) return this.abort()

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
          this.otr._smcb('trust', this.otr.trust)
          break

        case CONST.SMPSTATE_EXPECT4:
          HLP.debug.call(this.otr, 'smp tlv 5')

          // 0:r, 1:cR, 2:d7
          ms = HLP.readLen(msg.msg.substr(0, 4))
          if (ms !== 3) return this.abort()
          msg = HLP.unpackMPIs(3, msg.msg.substring(4))

          if (!HLP.checkGroup(msg[0], N)) return this.abort()

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
          this.otr._smcb('trust', this.otr.trust)
          return

      }

      this.sendMsg(send)
    },

    // send a message
    sendMsg: function (send) {
      this.otr._sendMsg('\x00' + send)
    },

    rcvSecret: function (secret, question) {
      HLP.debug.call(this.otr, 'receive secret')
      this.otr._status_cb(OTR.Status.SMP_RECEIVE_SECRET)

      if (this.otr.msgstate !== CONST.MSGSTATE_ENCRYPTED)
        return this.otr.error('Not ready to send encrypted messages.')

      var fn, our = false
      if (this.smpstate === CONST.SMPSTATE_EXPECT0) {
        fn = this.answer
      } else {
        fn = this.initiate
        our = true
      }

      this.makeSecret(our, secret)
      fn.call(this, question)
    },

    answer: function () {
      HLP.debug.call(this.otr, 'smp answer')
      this.otr._status_cb(OTR.Status.SMP_ANSWER)
      
      var r4 = HLP.randomExponent()
      this.computePQ(r4)

      // zero-knowledge proof that P & Q
      // were generated according to the protocol
      var r5 = HLP.randomExponent()
      var r6 = HLP.randomExponent()
      var tmp = HLP.multPowMod(G, r5, this.g2, r6, N)
      var cP = HLP.smpHash(5, BigInt.powMod(this.g3, r5, N), tmp)
      var d5 = this.computeD(r5, r4, cP)
      var d6 = this.computeD(r6, this.secret, cP)

      this.smpstate = CONST.SMPSTATE_EXPECT3

      var send = HLP.packINT(11) + HLP.packMPIs([
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

      this.sendMsg(HLP.packTLV(3, send))
    },

    initiate: function (question) {
      HLP.debug.call(this.otr, 'smp initiate')
      this.otr._status_cb(OTR.Status.SMP_INIT)

      if (this.smpstate !== CONST.SMPSTATE_EXPECT1)
        this.abort()  // abort + restart

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
      this.smpstate = CONST.SMPSTATE_EXPECT2

      var send = ''
      var type = 2

      if (question) {
        send += question
        send += '\x00'
        type = 7
      }

      send += HLP.packINT(6) + HLP.packMPIs([
          this.g2a
        , this.c2
        , this.d2
        , this.g3a
        , this.c3
        , this.d3
      ])

      this.sendMsg(HLP.packTLV(type, send))
    },

    abort: function () {
      this.otr.trust = false
      this.init()
      this.sendMsg(HLP.packTLV(6, ''))
      this.otr._smcb('trust', this.otr.trust)
    }

  }

}).call(this)