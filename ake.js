;(function () {

  var root = this

  if (typeof exports !== 'undefined') {
    module.exports = AKE
  } else {
    root.AKE = AKE
  }

  var CryptoJS = root.CryptoJS
    , BigInt = root.BigInt
    , DH = root.DH
    , SM = root.SM
    , HLP = root.HLP
    , DSA = root.DSA

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    BigInt || (BigInt = require('./vendor/bigint.js'))
    DH || (DH = require('./dh.json'))
    SM || (SM = require('./sm.js'))
    HLP || (HLP = require('./helpers.js'))
    DSA || (DSA = require('./dsa.js'))
  }

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)
  var TWO = BigInt.str2bigInt('2', 10)
  var N_MINUS_2 = BigInt.sub(N, TWO)

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

  // helpers
  function checkGroup(g) {
    return HLP.GTOE(g, TWO) && HLP.GTOE(N_MINUS_2, g)
  }

  function hMac(gx, gy, pk, kid, m) {
    var pass = CryptoJS.enc.Latin1.parse(m)
    var hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, pass)
    hmac.update(HLP.packMPI(gx))
    hmac.update(HLP.packMPI(gy))
    hmac.update(pk)
    hmac.update(kid)
    return (hmac.finalize()).toString(CryptoJS.enc.Latin1)
  }

  function L1toBI(l) {
    l = CryptoJS.enc.Latin1.parse(l)
    l = CryptoJS.enc.Hex.stringify(l)
    return BigInt.str2bigInt(l, 16)
  }

  // AKE constructor
  function AKE(otr) {
    if (!(this instanceof AKE)) return new AKE(otr)

    // otr instance
    this.otr = otr

    // our keys
    this.our_dh = otr.our_old_dh
    this.our_keyid = 1

    // their keys
    this.their_y = null
    this.their_keyid = null
    this.their_priv_pk = null

    // state
    this.ssid = null
    this.transmittedRS = false
    this.r = null
    this.priv = otr.priv

  }

  AKE.prototype = {

    constructor: AKE,

    createKeys: function(g) {
      var s = BigInt.powMod(g, this.our_dh.privateKey, N)
      var secbytes = HLP.packMPI(s)
      this.ssid = HLP.mask(HLP.h2('\x00', secbytes), 0, 64)  // first 64-bits
      var tmp = HLP.h2('\x01', secbytes)
      this.c = HLP.mask(tmp, 0, 128)  // first 128-bits
      this.c_prime = HLP.mask(tmp, 128, 128)  // second 128-bits
      this.m1 = HLP.h2('\x02', secbytes)
      this.m2 = HLP.h2('\x03', secbytes)
      this.m1_prime = HLP.h2('\x04', secbytes)
      this.m2_prime = HLP.h2('\x05', secbytes)
    },

    verifySignMac: function (mac, aesctr, m2, c, their_y, our_dh_pk, m1, ctr) {
      // verify mac
      var vmac = HLP.makeMac(aesctr, m2)
      if (mac !== vmac) return ['MACs do not match.']

      // decrypt x
      var x = HLP.decryptAes(aesctr.substring(4), c, ctr)
      x = HLP.splitype(['PUBKEY', 'INT', 'SIG'], x)

      var m = hMac(their_y, our_dh_pk, x[0], x[1], m1)
      var pub = DSA.parsePublic(x[0])

      var r = HLP.bits2bigInt(x[2].substring(0, 20))
      var s = HLP.bits2bigInt(x[2].substring(20))

      // verify sign m
      if (!DSA.verify(pub, m, r, s)) return ['Cannot verify signature of m.']

      return [null, HLP.readLen(x[1]), pub]
    },

    makeM: function (their_y, m1, c, m2) {
      var pk = this.priv.packPublic()
      var kid = HLP.packINT(this.our_keyid)
      var m = hMac(this.our_dh.publicKey, their_y, pk, kid, m1)
      m = this.priv.sign(m)
      var msg = pk + kid + HLP.bigInt2bits(m[0]) + HLP.bigInt2bits(m[1])
      var aesctr = HLP.packData(HLP.makeAes(msg, c, HLP.packCtr(0)))
      var mac = HLP.makeMac(aesctr, m2)
      return aesctr + mac
    },

    akeSuccess: function () {
      if (BigInt.equals(this.their_y, this.our_dh.publicKey))
        return this.otr.error('equal keys - we have a problem.', true)

      if ( this.their_keyid !== this.otr.their_keyid &&
           this.their_keyid !== (this.otr.their_keyid - 1) ) {

        // their keys
        this.otr.their_y = this.their_y
        this.otr.their_old_y = null
        this.otr.their_keyid = this.their_keyid
        this.otr.their_priv_pk = this.their_priv_pk
        DSA.inherit(this.otr.their_priv_pk)

        // rotate keys
        this.otr.sessKeys[0] = [ new this.otr.dhSession(
            this.otr.our_dh
          , this.otr.their_y
        ), null ]
        this.otr.sessKeys[1] = [ new this.otr.dhSession(
            this.otr.our_old_dh
          , this.otr.their_y
        ), null ]

      }

      // ake info
      this.otr.ssid = this.ssid
      this.otr.transmittedRS = this.transmittedRS
      this.otr.sm = new SM(this.otr)

      // go encrypted
      this.otr.authstate = AUTHSTATE_NONE
      this.otr.msgstate = MSGSTATE_ENCRYPTED

      // send stored msgs
      this.otr.sendStored()
    },

    handleAKE: function (msg) {

      var send, vsm
      switch (msg.type) {

        case '\x02':
          // d-h key message
          if (!this.otr.ALLOW_V2) return  // ignore

          msg = HLP.splitype(['DATA', 'DATA'], msg.msg)

          if (this.otr.authstate === AUTHSTATE_AWAITING_DHKEY) {
            var ourHash = L1toBI(this.myhashed)
            var theirHash = L1toBI(msg[1].substring(4))
            if (BigInt.greater(ourHash, theirHash)) {
              this.initiateAKE()
              return  // ignore
            } else {
              // forget
              this.our_dh = this.otr.dh()
              this.otr.AUTHSTATE_NONE
              this.r = null
              this.myhashed = null
            }
          } else if (
            this.otr.authstate === AUTHSTATE_AWAITING_SIG ||
            this.otr.authstate === AUTHSTATE_V1_SETUP
          ) this.our_dh = this.otr.dh()

          this.otr.authstate = AUTHSTATE_AWAITING_REVEALSIG

          this.encrypted = msg[0].substring(4)
          this.hashed = msg[1].substring(4)

          send = '\x0a'
          send += HLP.packMPI(this.our_dh.publicKey)
          break

        case '\x0a':
          // reveal signature message
          if (!this.otr.ALLOW_V2) return  // ignore

          msg = HLP.splitype(['MPI'], msg.msg)

          if (this.otr.authstate !== AUTHSTATE_AWAITING_DHKEY) {
            if (this.otr.authstate === AUTHSTATE_AWAITING_SIG) {
              if (!BigInt.equals(this.their_y, HLP.readMPI(msg[0]))) return
            } else {
              return  // ignore
            }
          }

          this.otr.authstate = AUTHSTATE_AWAITING_SIG

          this.their_y = HLP.readMPI(msg[0])

          // verify gy is legal 2 <= gy <= N-2
          if (!checkGroup(this.their_y))
            return this.otr.error('Illegal g^y.', true)

          this.createKeys(this.their_y)

          send = '\x11'
          send += HLP.packMPI(this.r)
          send += this.makeM(this.their_y, this.m1, this.c, this.m2)
          break

        case '\x11':
          // signature message
          if ( !this.otr.ALLOW_V2 ||
               this.otr.authstate !== AUTHSTATE_AWAITING_REVEALSIG
          ) return  // ignore

          msg = HLP.splitype(['DATA', 'DATA', 'MAC'], msg.msg)

          this.r = HLP.readMPI(msg[0])

          // decrypt their_y
          var key = CryptoJS.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
          key = CryptoJS.enc.Latin1.stringify(key)
          var gxmpi = HLP.decryptAes(this.encrypted, key, HLP.packCtr(0))

          this.their_y = HLP.readMPI(gxmpi)

          // verify hash
          var hash = CryptoJS.SHA256(gxmpi)

          if (this.hashed !== hash.toString(CryptoJS.enc.Latin1))
            return this.otr.error('Hashed g^x does not match.', true)

          // verify gx is legal 2 <= g^x <= N-2
          if (!checkGroup(this.their_y))
            return this.otr.error('Illegal g^x.', true)

          this.createKeys(this.their_y)

          vsm = this.verifySignMac(
              msg[2]
            , msg[1]
            , this.m2
            , this.c
            , this.their_y
            , this.our_dh.publicKey
            , this.m1
            , HLP.packCtr(0)
          )
          if (vsm[0]) return this.otr.error(vsm[0], true)

          // store their key
          this.their_keyid = vsm[1]
          this.their_priv_pk = vsm[2]

          send = '\x12'
          send += this.makeM(
              this.their_y
            , this.m1_prime
            , this.c_prime
            , this.m2_prime
          )
          this.sendMsg(send)

          this.akeSuccess()
          return

        case '\x12':
          // data message
          if ( !this.otr.ALLOW_V2 ||
               this.otr.authstate !== AUTHSTATE_AWAITING_SIG
          ) return  // ignore

          msg = HLP.splitype(['DATA', 'MAC'], msg.msg)

          vsm = this.verifySignMac(
              msg[1]
            , msg[0]
            , this.m2_prime
            , this.c_prime
            , this.their_y
            , this.our_dh.publicKey
            , this.m1_prime
            , HLP.packCtr(0)
          )
          if (vsm[0]) return this.otr.error(vsm[0], true)

          // store their key
          this.their_keyid = vsm[1]
          this.their_priv_pk = vsm[2]

          this.transmittedRS = true
          this.akeSuccess()
          return

        default:
          return  // ignore

      }

      this.sendMsg(send)
    },

    sendMsg: function (msg) {
      msg = '\x00\x02' + msg
      this.otr.sendMsg(HLP.wrapMsg(msg), true)
    },

    initiateAKE: function () {
      // d-h commit message
      var send = '\x02'

      this.otr.authstate = AUTHSTATE_AWAITING_DHKEY

      var gxmpi = HLP.packMPI(this.our_dh.publicKey)

      this.r = HLP.randomValue()
      var key = CryptoJS.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
      key = CryptoJS.enc.Latin1.stringify(key)
      send += HLP.packData(HLP.makeAes(gxmpi, key, HLP.packCtr(0)))

      this.myhashed = CryptoJS.SHA256(gxmpi)
      this.myhashed = HLP.packData(this.myhashed.toString(CryptoJS.enc.Latin1))
      send += this.myhashed

      this.sendMsg(send)
    }

  }

}).call(this)