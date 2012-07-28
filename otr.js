;(function () {

  var root = this

  if (typeof exports !== 'undefined') {
    module.exports = OTR
  } else {
    root.OTR = OTR
  }

  var AES = root.AES
    , SHA256 = root.SHA256
    , HmacSHA256 = root.HmacSHA256
    , BigInt = root.BigInt
    , DH = root.DH
    , hlp = root.hlp
    , dsa = root.dsa

  if (typeof require !== 'undefined') {
    AES || (AES = require('./vendor/aes.js'))
    BigInt || (BigInt = require('./vendor/bigint.js'))
    SHA256 || (SHA256 = require('./vendor/sha256.js'))
    HmacSHA256 || (HmacSHA256 = require('./vendor/hmac-sha256.js'))
    DH || (DH = require('./dh.json'))
    hlp || (hlp = require('./helpers.js'))
    dsa || (dsa = require('./dsa.js'))

    // ctr mode
    require('./vendor/mode-ctr.js')(AES)

    // no padding
    require('./vendor/pad-nopadding.js')(AES)
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

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)
  var TWO = BigInt.str2bigInt('2', 10)
  var N_MINUS_2 = BigInt.sub(N, TWO)

  function checkGroup(g) {
    return hlp.GTOE(g, TWO) && hlp.GTOE(N_MINUS_2, g)
  }

  function dh() {
    var keys = { privateKey: BigInt.randBigInt(320) }
    keys.publicKey = BigInt.powMod(G, keys.privateKey, N)
    return keys
  }

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
      this.keyId = 0
      this.priv = new dsa.Key()
      this.dh = dh()
    },

    createAuthKeys: function(g) {
      var s = BigInt.powMod(g, this.dh.privateKey, N)
      var secbytes = hlp.packMPI(s)
      this.ssid = hlp.mask(hlp.h2('\x00', secbytes), 0, 64)  // first 64-bits
      var tmp = hlp.h2('\x01', secbytes)
      this.c = hlp.mask(tmp, 0, 128)  // first 128-bits
      this.c_prime = hlp.mask(tmp, 128, 128)  // second 128-bits
      this.m1 = hlp.h2('\x02', secbytes)
      this.m2 = hlp.h2('\x03', secbytes)
      this.m1_prime = hlp.h2('\x04', secbytes)
      this.m2_prime = hlp.h2('\x05', secbytes)
    },

    calculatePubkeyAuth: function(gx, gy, pk, kid, m) {
      var pass = HmacSHA256.enc.Latin1.parse(m)
      var hmac = HmacSHA256.algo.HMAC.create(HmacSHA256.algo.SHA256, pass)
      hmac.update(hlp.packMPI(gx))
      hmac.update(hlp.packMPI(gy))
      hmac.update(pk)
      hmac.update(kid)
      return (hmac.finalize()).toString(HmacSHA256.enc.Latin1)
    },

    makeAes: function (pk, kid, m, c) {
      var sign = this.priv.sign(m)
      var x = pk + kid + hlp.packMPI(sign[0]) + hlp.packMPI(sign[1])
      var opts = {
          mode: AES.mode.CTR
        , iv: AES.enc.Latin1.parse(0)
        , padding: AES.pad.NoPadding
      }
      var aesctr = AES.AES.encrypt(
          AES.enc.Latin1.parse(x)
        , AES.enc.Latin1.parse(c)
        , opts
      )
      return aesctr.toString()
    },

    makeMac: function (aesctr, m) {
      var pass = HmacSHA256.enc.Latin1.parse(m)
      var mac = HmacSHA256.HmacSHA256(aesctr, pass)
      return hlp.mask(mac.toString(HmacSHA256.enc.Latin1), 0, 160)
    },

    verifySignMac: function (msg, m2, c, gx, gy, m1) {
      // verify mac
      var mac = this.makeMac(msg.aesctr, m2)
      if (msg.mac !== mac) return 'MACs do not match.'

      // decrypt x
      var opts = {
          mode: AES.mode.CTR
        , iv: AES.enc.Latin1.parse(0)
        , padding: AES.pad.NoPadding
      }

      var aesctr = AES.AES.decrypt(
          msg.aesctr
        , AES.enc.Latin1.parse(c)
        , opts
      )

      var x = aesctr.toString(AES.enc.Latin1)
      x = hlp.parseToStrs(x)

      var m = this.calculatePubkeyAuth(gx, gy, x[0], x[1], m1)
      var pub = dsa.parsePublic(x[0])

      // verify sign m
      if (!dsa.verify(pub, m, hlp.readMPI(x[2]), hlp.readMPI(x[3])))
        return 'Cannot verify signature of m.'
    },

    makeM: function (send, g, m1, c, m2) {
      var pk = this.priv.packPublic()
      var kid = hlp.packData(hlp.pack(this.keyId))
      var m = this.calculatePubkeyAuth(this.dh.publicKey, g, pk, kid, m1)
      send.aesctr = this.makeAes(pk, kid, m, c)
      send.mac = this.makeMac(send.aesctr, m2)
    },

    handleAKE: function (msg, cb) {
      var opts
        , reply = true
        , send = {}
        , err

      switch (msg.type) {

        case '\x02':
          // d-h key message
          send.gy = hlp.packMPI(this.dh.publicKey)
          this.encrypted = msg.encrypted
          this.hashed = msg.hashed
          send.type = '\x0a'
          send.version = '\x00\x02'
          break

        case '\x0a':
          // reveal signature message
          this.gy = hlp.readMPI(msg.gy)

          // verify gy is legal 2 <= gy <= N-2
          if (!checkGroup(this.gy)) return this.error('Illegal g^y.')

          this.createAuthKeys(this.gy)
          this.keyId += 1
          this.makeM(send, this.gy, this.m1, this.c, this.m2)

          send.r = hlp.packMPI(this.r)
          send.type = '\x11'
          send.version = '\x00\x02'
          break

        case '\x11':
          // signature message
          this.r = hlp.readMPI(msg.r)

          var key = AES.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
          opts = {
              mode: AES.mode.CTR
            , iv: AES.enc.Latin1.parse(0)
            , padding: AES.pad.NoPadding
          }
          var gxmpi = AES.AES.decrypt(this.encrypted, key, opts)
          gxmpi = gxmpi.toString(AES.enc.Latin1)
          this.gx = hlp.readMPI(gxmpi)

          // verify hash
          var hash = SHA256.SHA256(gxmpi)
          if (this.hashed !== hash.toString(SHA256.enc.Latin1))
            return this.error('Hashed g^x does not match.')

          // verify gx is legal 2 <= gy <= N-2
          if (!checkGroup(this.gx)) return this.error('Illegal g^x.')

          this.createAuthKeys(this.gx)

          err = this.verifySignMac(
              msg
            , this.m2
            , this.c
            , this.gx
            , this.dh.publicKey
            , this.m1
          )
          if (err) return this.error(err)

          this.keyId += 1
          this.makeM(send, this.gx, this.m1_prime, this.c_prime, this.m2_prime)

          send.type = '\x12'
          send.version = '\x00\x02'
          break

        case '\x12':
          // data message
          err = this.verifySignMac(
              msg
            , this.m2_prime
            , this.c_prime
            , this.gy
            , this.dh.publicKey
            , this.m1_prime
          )
          if (err) return this.error(err)

          send.type = '\x03'
          send.version = '\x00\x02'
          break

        case '\x03':
          reply = false
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
         type: '\x02'
       , version: '\x00\x02'
      }

      var gxmpi = hlp.packMPI(this.dh.publicKey)

      this.r = hlp.randomValue()
      var key = AES.enc.Hex.parse(BigInt.bigInt2str(this.r, 16))
      var opts = {
          mode: AES.mode.CTR
        , iv: AES.enc.Latin1.parse(0)
        , padding: AES.pad.NoPadding
      }

      var encrypt = AES.AES.encrypt(AES.enc.Latin1.parse(gxmpi), key, opts)
      send.encrypted = encrypt.toString()

      var hash = SHA256.SHA256(gxmpi)
      send.hashed = hash.toString(SHA256.enc.Latin1)

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

}).call(this)