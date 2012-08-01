;(function () {

  var root = this

  if (typeof exports !== 'undefined') {
    module.exports = OTR
  } else {
    root.OTR = OTR
  }

  var CryptoJS = root.CryptoJS
    , BigInt = root.BigInt
    , DH = root.DH
    , HLP = root.HLP
    , SM = root.SM
    , DSA = root.DSA
    , ParseOTR = root.ParseOTR

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    BigInt || (BigInt = require('./vendor/bigint.js'))
    DH || (DH = require('./dh.json'))
    HLP || (HLP = require('./helpers.js'))
    SM || (SM = require('./sm.js'))
    DSA || (DSA = require('./dsa.js'))
    ParseOTR || (ParseOTR = require('./parse.js'))
  }

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
    , AUTHSTATE_V2_SETUP = 5

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)
  var TWO = BigInt.str2bigInt('2', 10)
  var N_MINUS_2 = BigInt.sub(N, TWO)

  // otr message wrapper begin and end
  var WRAPPER_BEGIN = "?OTR:"
  var WRAPPER_END = "."

  // some helpers
  function checkGroup(g) {
    return HLP.GTOE(g, TWO) && HLP.GTOE(N_MINUS_2, g)
  }

  function dh() {
    var keys = { privateKey: BigInt.randBigInt(320) }
    keys.publicKey = BigInt.powMod(G, keys.privateKey, N)
    return keys
  }

  function wrapMsg(msg) {
    msg = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(msg))
    return WRAPPER_BEGIN + msg + WRAPPER_END
  }

  function makeAes(msg, c, iv) {
    var opts = {
        mode: CryptoJS.mode.CTR
      , iv: CryptoJS.enc.Latin1.parse(iv)
      , padding: CryptoJS.pad.NoPadding
    }
    var aesctr = CryptoJS.AES.encrypt(
        CryptoJS.enc.Latin1.parse(msg)
      , CryptoJS.enc.Latin1.parse(c)
      , opts
    )

    var aesctr_decoded = CryptoJS.enc.Base64.parse(aesctr.toString())
    return CryptoJS.enc.Latin1.stringify(aesctr_decoded)
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

  function makeMac(aesctr, m) {
    var pass = CryptoJS.enc.Latin1.parse(m)
    var mac = CryptoJS.HmacSHA256(aesctr, pass)
    return HLP.mask(mac.toString(CryptoJS.enc.Latin1), 0, 160)
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

  // session constructor
  function dhSession(our_dh, their_y) {
    if (!(this instanceof dhSession)) return new dhSession(our_dh, their_y)

    // shared secret
    var s = BigInt.powMod(their_y, our_dh.privateKey, N)
    var secbytes = HLP.packMPI(s)

    // session id
    this.id = HLP.mask(HLP.h2('\x00', secbytes), 0, 64)  // first 64-bits
    var tmp = HLP.h2('\x01', secbytes)

    // are we the high or low end of the connection?
    var sq = BigInt.greater(our_dh.publicKey, their_y)
    var sendbyte = sq ? '\x01' : '\x02'
    var rcvbyte =  sq ? '\x02' : '\x01'

    // sending and receiving keys
    this.sendenc = HLP.mask(HLP.h1(sendbyte, secbytes), 0, 128)  // f16 bytes
    this.sendmac = CryptoJS.SHA1(this.sendenc)
    this.sendmacused = false
    this.rcvenc = HLP.mask(HLP.h1(rcvbyte, secbytes), 0, 128)
    this.rcvmac = CryptoJS.SHA1(this.rcvenc)
    this.rcvmacused = false

    // counter
    this.counter = 0
  }

  // AKE constructor
  function AKE(otr) {
    if (!(this instanceof AKE)) return new AKE(otr)

    if (!(otr instanceof OTR)) throw new Error('Not OTR instance.')
    this.otr = otr

    this.our_dh = otr.our_dh
    this.our_keyid = 1

    this.their_y = null
    this.their_keyid = null
    this.their_priv_pk = null

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
      var aesctr = makeAes(msg, c, 0)
      var mac = makeMac(aesctr, m2)
      return aesctr + mac
    },

    akeSuccess: function () {
      if (BigInt.equals(this.their_y, this.our_dh.publicKey))
        throw new Error('equal keys - we have a problem.')

      // their keys
      this.otr.their_y = this.their_y
      this.otr.their_keyid = this.their_keyid
      this.otr.their_priv_pk = this.their_priv_pk

      // ake info
      this.otr.ssid = this.ssid
      this.otr.transmittedRS = this.transmittedRS

      // rotate keys
      this.otr.sessKeys[0][0] = dhSession(this.otr.our_dh, this.otr.their_y)
      this.otr.rotateOurKeys()

      // go encrypted
      this.otr.msgstate = MSGSTATE_ENCRYPTED
    },

    handleAKE: function (msg) {

      var send, err
      switch (msg.type) {

        case '\x02':
          // d-h key message
          if (this.otr.authstate !== AUTHSTATE_NONE) {
            // something something
          }
          this.otr.authstate = AUTHSTATE_AWAITING_REVEALSIG

          send = '\x0a'
          send += HLP.packMPI(this.our_dh.publicKey)

          // parse out these vals
          this.encrypted = msg.encrypted
          this.hashed = msg.hashed
          break

        case '\x0a':
          // reveal signature message
          if (this.otr.authstate !== AUTHSTATE_AWAITING_DHKEY) {
            // something something
          }
          this.otr.authstate = AUTHSTATE_AWAITING_SIG

          this.their_y = HLP.readMPI(msg.gy)

          // verify gy is legal 2 <= gy <= N-2
          if (!checkGroup(this.their_y)) return this.error('Illegal g^y.')

          this.createKeys(this.their_y)

          send.type = '\x11'
          send += HLP.packMPI(this.r)
          send += this.makeM(this.their_y, this.m1, this.c, this.m2)
          break

        case '\x11':
          // signature message
          if (this.otr.authstate !== AUTHSTATE_AWAITING_REVEALSIG) {
            // something something
          }
          this.otr.authstate = AUTHSTATE_V2_SETUP

          this.r = HLP.readMPI(msg.r)

          // decrypt their_y
          var key = CryptoJS.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
          var gxmpi = decryptAes(this.encrypted, key, 0)
          this.their_y = HLP.readMPI(gxmpi)

          // verify hash
          var hash = CryptoJS.SHA256(gxmpi)
          if (this.hashed !== hash.toString(CryptoJS.enc.Latin1))
            return this.error('Hashed g^x does not match.')

          // verify gx is legal 2 <= g^x <= N-2
          if (!checkGroup(this.their_y)) return this.error('Illegal g^x.')

          this.createKeys(this.their_y)

          err = this.verifySignMac(
              msg
            , this.m2
            , this.c
            , this.their_y
            , this.our_dh.publicKey
            , this.m1
          )
          if (err) return this.error(err)

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
          if (this.otr.authstate !== AUTHSTATE_AWAITING_SIG) {
            // something something
          }
          this.otr.authstate = AUTHSTATE_V2_SETUP

          err = this.verifySignMac(
              msg
            , this.m2_prime
            , this.c_prime
            , this.their_y
            , this.our_dh.publicKey
            , this.m1_prime
          )
          if (err) return this.error(err)

          this.transmittedRS = true
          this.akeSuccess()
          break

        default:
          return this.error('Invalid message type.')

      }

      return this.sendMsg(send)
    },

    sendMsg: function (msg) {
      msg = '\x00\x02' + msg
      return this.otr.sendMsg(wrapMsg(msg))
    },

    initiateAKE: function () {
      // d-h commit message
      var send =  '\x02'

      if (this.otr.authstate !== AUTHSTATE_NONE) {
        // something something
      }
      this.otr.authstate = AUTHSTATE_AWAITING_DHKEY

      var gxmpi = HLP.packMPI(this.our_dh.publicKey)

      this.r = HLP.randomValue()
      var key = CryptoJS.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
      send += HLP.packData(makeAes(gxmpi, key, 0))

      var hash = CryptoJS.SHA256(gxmpi)
      send += HLP.packData(hash.toString(CryptoJS.enc.Latin1))

      return this.sendMsg(send)
    }

  }

  // OTR contructor
  function OTR(priv) {
    if (!(this instanceof OTR)) return new OTR(priv)

    if (priv && !(priv instanceof DSA.Key))
      throw new Error('Requires long-lived DSA key.')

    this.priv = priv ? priv : new DSA.Key()

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

      ParseOTR.initFragment(this)

      this.versions = {}

      // their keys
      this.their_y = null
      this.their_old_y = null
      this.their_keyid = 0
      this.their_priv_pk = null

      // our keys
      this.our_dh = new dh()
      this.our_old_dh = new dh()
      this.our_keyid = 2

      // session keys
      this.sessKeys = [ new Array(2), new Array(2) ]

      this.oldMacKeys = []

      this.sm = null  // new SM()

      // when ake is complete
      // save their keys and the session
      this.ake = new AKE(this)
      this.transmittedRS = false
      this.ssid = null

    },

    rotateOurKeys: function () {

      // reveal old mac keys
      this.sessKeys[1].forEach(function (sk) {
        if (sk.sendmacused) this.oldMacKeys.push(sk.sendmac)
        if (sk.rcvmacused) this.oldMacKeys.push(sk.rcvmac)
      })

      // rotate our keys
      this.our_old_dh = this.our_dh
      this.our_dh = new dh()
      this.our_keyid += 1

      // session keys
      this.sessKeys[1] = this.sessKeys[0]
      this.sessKeys[0] = [
          this.their_y ? new dhSession(this.our_dh, this.their_y) : null
        , this.their_old_y ? new dhSession(this.our_dh, this.their_old_y) : null
      ]

    },

    rotateTheirKeys: function (their_y) {

      // reveal old mac keys
      this.sessKeys.forEach(function (sk) {
        if (sk[1].sendmacused) this.oldMacKeys.push(sk[1].sendmac)
        if (sk[1].rcvmacused) this.oldMacKeys.push(sk[1].rcvmac)
      })

      // rotate their keys / session
      this.their_old_y = this.their_y
      this.sessKeys[0][1] = this.sessKeys[0][0]
      this.sessKeys[1][1] = this.sessKeys[1][0]

      // new keys / sessions
      this.their_y = their_y
      this.sessKeys[0][0] = new dhSession(this.our_dh, this.their_y)
      this.sessKeys[1][0] = new dhSession(this.our_old_dh, this.their_y)

    },

    prepareMsg: function (msg) {

      if (this.msgstate !== MSGSTATE_ENCRYPTED || this.their_keyid === 0)
        return this.error('Not ready to encrypt.')

      var sessKeys = this.sessKeys[1][0]
      sessKeys.counter += 1

      var oldMacKeys = this.oldMacKeys.join('')
      this.oldMacKeys = []

      var ta = HLP.packInt(this.our_keyid - 1)
      ta += HLP.packInt(this.their_keyid)
      ta += HLP.packMPI(this.our_dh.publicKey)
      ta += HLP.packInt(sessKeys.counter)
      ta += makeAes(msg, sessKeys.sendenc, sessKeys.counter)

      var mta = makeMac(ta, sessKeys.sendmac)

      return wrapMsg(ta + mta + oldMacKeys)

    },

    sendMsg: function (msg, retcb) {
      if (retcb) this.retcb = retcb
      if (this.msgstate === MSGSTATE_ENCRYPTED) msg = this.prepareMsg(msg)
      this.retcb(msg)
    },

    receiveMsg: function (msg, uicb, retcb) {
      this.uicb = uicb
      this.retcb = retcb
      msg = ParseOTR.parseMsg(this, msg)
    },

    error: function (err) {
      console.log(err)
      return ''
    }

  }

}).call(this)
