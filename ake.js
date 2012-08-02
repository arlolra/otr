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
    , HLP = root.HLP
    , DSA = root.DSA

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    BigInt || (BigInt = require('./vendor/bigint.js'))
    DH || (DH = require('./dh.json'))
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

  function decryptAes(msg, c, iv) {
    var opts = {
        mode: CryptoJS.mode.CTR
      , iv: CryptoJS.enc.Latin1.parse(iv)
      , padding: CryptoJS.pad.NoPadding
    }
    var aesctr = CryptoJS.AES.decrypt(
        msg
      , CryptoJS.enc.Latin1.parse(c)
      , opts
    )
    return aesctr.toString(CryptoJS.enc.Latin1)
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
    this.our_dh = otr.our_dh
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

    verifySignMac: function (msg, m2, c, their_y, our_dh_pk, m1) {
      // verify mac
      var mac = this.makeMac(msg.aesctr, m2)
      if (msg.mac !== mac) return 'MACs do not match.'

      // decrypt x
      var x = decryptAes(msg.aesctr, c, 0)
      x = HLP.parseToStrs(x)

      var m = hMac(their_y, our_dh_pk, x[0], x[1], m1)
      var pub = DSA.parsePublic(x[0])

      // verify sign m
      if (!DSA.verify(pub, m, HLP.readMPI(x[2]), HLP.readMPI(x[3])))
        return 'Cannot verify signature of m.'

      // store their key
      this.their_keyid = HLP.readInt(x[1])
      this.their_priv_pk = pub
    },

    makeM: function (their_y, m1, c, m2) {
      var pk = this.priv.packPublic()
      var kid = HLP.packInt(this.our_keyid)
      var m = hMac(this.our_dh.publicKey, their_y, pk, kid, m1)
      m = this.priv.sign(m)
      var msg = pk + kid + HLP.packMPI(m[0]) + HLP.packMPI(m[1])
      var aesctr = HLP.makeAes(msg, c, 0)
      var mac = HLP.makeMac(aesctr, m2)
      return aesctr + mac
    },

    akeSuccess: function () {
      if (BigInt.equals(this.their_y, this.our_dh.publicKey))
        return this.otr.error('equal keys - we have a problem.', true)

      // our keys
      this.otr.our_dh = this.dh

      // their keys
      this.otr.their_y = this.their_y
      this.otr.their_keyid = this.their_keyid
      this.otr.their_priv_pk = this.their_priv_pk

      // ake info
      this.otr.ssid = this.ssid
      this.otr.transmittedRS = this.transmittedRS

      // rotate keys
      this.otr.sessKeys[0][0] = new this.otr.dhSession(
          this.otr.our_dh
        , this.otr.their_y
      )
      this.otr.rotateOurKeys()

      // go encrypted
      this.otr.authstate = AUTHSTATE_NONE
      this.otr.msgstate = MSGSTATE_ENCRYPTED

      // send stored msgs
      this.otr.sendStored()
    },

    handleAKE: function (msg) {

      var send, err
      switch (msg.type) {

        case '\x02':
          // d-h key message
          if (!this.otr.ALLOW_V2) return  // ignore

          if (this.otr.authstate === AUTHSTATE_AWAITING_DHKEY) {
            var ourHash = L1toBI(this.myhashed)
            var theirHash = L1toBI(msg.hashed)
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

          send = '\x0a'
          send += HLP.packMPI(this.our_dh.publicKey)

          // parse out these vals
          this.encrypted = msg.encrypted
          this.hashed = msg.hashed
          break

        case '\x0a':
          // reveal signature message
          if (!this.otr.ALLOW_V2) return  // ignore

          if (this.otr.authstate !== AUTHSTATE_AWAITING_DHKEY) {
            if (this.otr.authstate === AUTHSTATE_AWAITING_SIG) {
              if (!BigInt.equals(this.their_y, HLP.readMPI(msg.gy))) return
            } else {
              return  // ignore
            }
          }

          this.otr.authstate = AUTHSTATE_AWAITING_SIG

          this.their_y = HLP.readMPI(msg.gy)

          // verify gy is legal 2 <= gy <= N-2
          if (!checkGroup(this.their_y))
            return this.otr.error('Illegal g^y.', true)

          this.createKeys(this.their_y)

          send.type = '\x11'
          send += HLP.packMPI(this.r)
          send += this.makeM(this.their_y, this.m1, this.c, this.m2)
          break

        case '\x11':
          // signature message
          if ( !this.otr.ALLOW_V2 ||
               this.otr.authstate !== AUTHSTATE_AWAITING_REVEALSIG
          ) return  // ignore

          this.r = HLP.readMPI(msg.r)

          // decrypt their_y
          var key = CryptoJS.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
          var gxmpi = decryptAes(this.encrypted, key, 0)
          this.their_y = HLP.readMPI(gxmpi)

          // verify hash
          var hash = CryptoJS.SHA256(gxmpi)
          if (this.hashed !== hash.toString(CryptoJS.enc.Latin1))
            return this.otr.error('Hashed g^x does not match.', true)

          // verify gx is legal 2 <= g^x <= N-2
          if (!checkGroup(this.their_y))
            return this.otr.error('Illegal g^x.', true)

          this.createKeys(this.their_y)

          err = this.verifySignMac(
              msg
            , this.m2
            , this.c
            , this.their_y
            , this.our_dh.publicKey
            , this.m1
          )
          if (err) return this.otr.error(err, true)

          this.akeSuccess()

          send = '\x12'
          send += this.makeM(
              this.their_y
            , this.m1_prime
            , this.c_prime
            , this.m2_prime
          )
          break

        case '\x12':
          // data message
          if ( !this.otr.ALLOW_V2 ||
               this.otr.authstate !== AUTHSTATE_AWAITING_SIG
          ) return  // ignore

          err = this.verifySignMac(
              msg
            , this.m2_prime
            , this.c_prime
            , this.their_y
            , this.our_dh.publicKey
            , this.m1_prime
          )
          if (err) return this.otr.error(err, true)

          this.transmittedRS = true
          this.akeSuccess()
          break

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
      send += HLP.packData(HLP.makeAes(gxmpi, key, 0))

      this.myhashed = CryptoJS.SHA256(gxmpi)
      this.myhashed = HLP.packData(this.myhashed.toString(CryptoJS.enc.Latin1))
      send += this.myhashed

      this.sendMsg(send)
    }

  }

}).call(this)