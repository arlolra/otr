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
    , AKE = root.AKE
    , DSA = root.DSA
    , ParseOTR = root.ParseOTR

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    BigInt || (BigInt = require('./vendor/bigint.js'))
    DH || (DH = require('./dh.json'))
    HLP || (HLP = require('./helpers.js'))
    SM || (SM = require('./sm.js'))
    DSA || (DSA = require('./dsa.js'))
    AKE || (AKE = require('./ake.js'))
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

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)

  // OTR contructor
  function OTR(priv, uicb, iocb) {
    if (!(this instanceof OTR)) return new OTR(priv, uicb, iocb)

    // private keys
    if (priv && !(priv instanceof DSA.Key))
      throw new Error('Requires long-lived DSA key.')

    this.priv = priv ? priv : new DSA.Key()

    // attach callbacks
    if ( !iocb || typeof iocb !== 'function' ||
         !uicb || typeof uicb !== 'function'
    ) throw new Error('UI and IO callbacks are required.')

    this.iocb = iocb
    this.uicb = uicb

    // init vals
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

      this.REQUIRE_ENCRYPTION = false
      this.SEND_WHITESPACE_TAG = false
      this.WHITESPACE_START_AKE = false
      this.ERROR_START_AKE = false

      ParseOTR.initFragment(this)

      this.versions = {}

      // their keys
      this.their_y = null
      this.their_old_y = null
      this.their_keyid = 0
      this.their_priv_pk = null

      // our keys
      this.our_dh = this.dh()
      this.our_old_dh = this.dh()
      this.our_keyid = 2

      // session keys
      this.sessKeys = [ new Array(2), new Array(2) ]

      // saved
      this.storedMgs = []
      this.oldMacKeys = []

      this.sm = null  // new SM()

      // when ake is complete
      // save their keys and the session
      this.ake = new AKE(this)
      this.transmittedRS = false
      this.ssid = null

    },

    dh: function dh() {
      var keys = { privateKey: BigInt.randBigInt(320) }
      keys.publicKey = BigInt.powMod(G, keys.privateKey, N)
      return keys
    },

    // session constructor
    dhSession: function dhSession(our_dh, their_y) {
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
    },

    rotateOurKeys: function () {

      // reveal old mac keys
      this.sessKeys[1].forEach(function (sk) {
        if (sk.sendmacused) this.oldMacKeys.push(sk.sendmac)
        if (sk.rcvmacused) this.oldMacKeys.push(sk.rcvmac)
      })

      // rotate our keys
      this.our_old_dh = this.our_dh
      this.our_dh = this.dh()
      this.our_keyid += 1

      // session keys
      this.sessKeys[1] = this.sessKeys[0]
      this.sessKeys[0] = [
          this.their_y ?
              new this.dhSession(this.our_dh, this.their_y) : null
        , this.their_old_y ?
              new this.dhSession(this.our_dh, this.their_old_y) : null
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
      this.sessKeys[0][0] = new this.dhSession(this.our_dh, this.their_y)
      this.sessKeys[1][0] = new this.dhSession(this.our_old_dh, this.their_y)

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
      ta += HLP.makeAes(msg, sessKeys.sendenc, sessKeys.counter)

      var mta = HLP.makeMac(ta, sessKeys.sendmac)

      return HLP.wrapMsg(ta + mta + oldMacKeys)

    },

    handleDataMsg: function (msg) {
      // TODO
    },

    sendQueryMsg: function () {
      var versions = {}
        , msg = '?OTR'

      if (this.ALLOW_V2) versions['2'] = true
      if (this.ALLOW_V1) versions['1'] = true

      if (versions['1']) msg += '?'

      var vs = Object.keys(versions)
      if (vs.length) {
        msg += 'v'
        vs.forEach(function (v) {
          if (v !== '1') msg += v
        })
        msg += '?'
      }

      this.sendMsg(msg, true)
    },

    sendMsg: function (msg, internal) {
      if (!internal) {  // a user msg

        switch (this.msgstate) {
          case MSGSTATE_PLAINTEXT:
            if (this.REQUIRE_ENCRYPTION) {
              this.storedMgs.push(msg)
              this.sendQueryMsg()
              return
            }
            if (this.SEND_WHITESPACE_TAG) {
              // and haven't received a PT msg since entering PT
              // msg += whitespace_tag
            }
            break
          case MSGSTATE_FINISHED:
            this.storedMgs.push(msg)
            this.error('Message cannot be sent at this time.')
            return
            break
          default:
            this.storedMgs.push(msg)
            msg = this.prepareMsg(msg)
        }

      }
      this.iocb(msg)
    },

    receiveMsg: function (msg) {
      msg = ParseOTR.parseMsg(this, msg)
    },

    error: function (err, send) {
      if (this.debug) console.log(err)

      if (send) {
        err = '?OTR Error:' + err
        this.sendMsg(err, true)
        return
      }

      this.uicb(err)
    },

    sendStored: function () {
      (this.storedMgs.splice(0)).forEach(function (msg) {
        this.sendMsg(msg)
      })
    },

    endOtr: function () {
      if (this.msgstate === MSGSTATE_ENCRYPTED) {
        this.sendMsg('\x00\x01\x00\x00')
        this.sm = null
      }
      this.msgstate = MSGSTATE_PLAINTEXT
    }

  }

}).call(this)