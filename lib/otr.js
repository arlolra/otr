;(function () {

  var root = this

  if (typeof exports !== 'undefined') {
    module.exports = OTR
  } else {
    root.OTR = OTR
  }

  var CryptoJS = root.CryptoJS
    , BigInt = root.BigInt
    , EventEmitter = root.EventEmitter
    , DH = root.DH
    , HLP = root.HLP
    , AKE = root.AKE
    , DSA = root.DSA
    , STATES = root.STATES
    , ParseOTR = root.ParseOTR

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('../vendor/cryptojs/cryptojs.js'))
    BigInt || (BigInt = require('../vendor/bigint.js'))
    EventEmitter || (EventEmitter = require('../vendor/EventEmitter.min.js').EventEmitter)
    DH || (DH = require('./dh.js'))
    HLP || (HLP = require('./helpers.js'))
    DSA || (DSA = require('./dsa.js'))
    AKE || (AKE = require('./ake.js'))
    STATES || (STATES = require('./states.js'))
    ParseOTR || (ParseOTR = require('./parse.js'))
  }

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(DH.G, 10)
  var N = BigInt.str2bigInt(DH.N, 16)

  // OTR contructor
  function OTR(priv, uicb, iocb, options) {
    if (!(this instanceof OTR)) return new OTR(priv, uicb, iocb, options)
    
    // inherits EventEmitter
    EventEmitter.apply(this)

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

    // options
    options = options || {}

    this.fragment_size = options.fragment_size || 0
    if (!(this.fragment_size >= 0))
      throw new Error('Fragment size must be a positive integer.')

    this.send_interval = options.send_interval || 50
    if (!(this.send_interval >= 0))
      throw new Error('Send interval must be a positive integer.')

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
      this.msgstate = STATES.MSGSTATE_PLAINTEXT
      this.authstate = STATES.AUTHSTATE_NONE

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

      this.sm = null  // initialized after AKE
      this.trust = false  // will be true after successful smp

      // when ake is complete
      // save their keys and the session
      this.ake = new AKE(this)
      this.transmittedRS = false
      this.ssid = null

      // user provided secret for SM
      this.secret = 'cryptocat?'

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

      // are we the high or low end of the connection?
      var sq = BigInt.greater(our_dh.publicKey, their_y)
      var sendbyte = sq ? '\x01' : '\x02'
      var rcvbyte  = sq ? '\x02' : '\x01'

      // sending and receiving keys
      this.sendenc = HLP.mask(HLP.h1(sendbyte, secbytes), 0, 128)  // f16 bytes
      this.sendmac = CryptoJS.SHA1(CryptoJS.enc.Latin1.parse(this.sendenc))
      this.sendmac = this.sendmac.toString(CryptoJS.enc.Latin1)
      this.sendmacused = false
      this.rcvenc = HLP.mask(HLP.h1(rcvbyte, secbytes), 0, 128)
      this.rcvmac = CryptoJS.SHA1(CryptoJS.enc.Latin1.parse(this.rcvenc))
      this.rcvmac = this.rcvmac.toString(CryptoJS.enc.Latin1)
      this.rcvmacused = false

      // counters
      this.send_counter = 0
      this.rcv_counter = 0
    },

    rotateOurKeys: function () {

      // reveal old mac keys
      var self = this
      this.sessKeys[1].forEach(function (sk) {
        if (sk && sk.sendmacused) self.oldMacKeys.push(sk.sendmac)
        if (sk && sk.rcvmacused) self.oldMacKeys.push(sk.rcvmac)
      })

      // rotate our keys
      this.our_old_dh = this.our_dh
      this.our_dh = this.dh()
      this.our_keyid += 1

      this.sessKeys[1][0] = this.sessKeys[0][0]
      this.sessKeys[1][1] = this.sessKeys[0][1]
      this.sessKeys[0] = [
          this.their_y ?
              new this.dhSession(this.our_dh, this.their_y) : null
        , this.their_old_y ?
              new this.dhSession(this.our_dh, this.their_old_y) : null
      ]

    },

    rotateTheirKeys: function (their_y) {

      // increment their keyid
      this.their_keyid += 1

      // reveal old mac keys
      var self = this
      this.sessKeys.forEach(function (sk) {
        if (sk[1] && sk[1].sendmacused) self.oldMacKeys.push(sk[1].sendmac)
        if (sk[1] && sk[1].rcvmacused) self.oldMacKeys.push(sk[1].rcvmac)
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

    prepareMsg: function (msg, cb) {
      if (this.msgstate !== STATES.MSGSTATE_ENCRYPTED || this.their_keyid === 0)
        return cb('Not ready to encrypt.')

      var sessKeys = this.sessKeys[1][0]
      sessKeys.send_counter += 1

      var ctr = HLP.packCtr(sessKeys.send_counter)

      var send = '\x00\x02' + '\x03'  // version and type
      send += '\x00'  // flag
      send += HLP.packINT(this.our_keyid - 1)
      send += HLP.packINT(this.their_keyid)
      send += HLP.packMPI(this.our_dh.publicKey)
      send += ctr.substring(0, 8)
      send += HLP.packData(HLP.makeAes(msg, sessKeys.sendenc, ctr))
      send += HLP.make1Mac(send, sessKeys.sendmac)
      send += HLP.packData(this.oldMacKeys.splice(0).join(''))

      sessKeys.sendmacused = true

      HLP.wrapMsg(send, {
          fragment_size: this.fragment_size
        , send_interval: this.send_interval
      }, cb)
    },

    handleDataMsg: function (msg) {
      var vt = msg.version + msg.type

      var types = ['BYTE', 'INT', 'INT', 'MPI', 'CTR', 'DATA', 'MAC', 'DATA']
      msg = HLP.splitype(types, msg.msg)

      // ignore flag
      var ign = (msg[0] === '\x01')

      if (this.msgstate !== STATES.MSGSTATE_ENCRYPTED || msg.length !== 8) {
        if (!ign) this.error('Received an unreadable encrypted message.', true)
        return
      }

      var our_keyid = this.our_keyid - HLP.readLen(msg[2])
      var their_keyid = this.their_keyid - HLP.readLen(msg[1])

      if (our_keyid < 0 || our_keyid > 1) {
        if (!ign) this.error('Not of our latest keys.', true)
        return
      }

      var our_dh =  our_keyid ? this.our_old_dh : this.our_dh

      if (their_keyid < 0 || their_keyid > 1) {
        if (!ign) this.error('Not of your latest keys.', true)
        return
      }

      var their_y = their_keyid ? this.their_old_y : this.their_y

      if (their_keyid === 1 && !their_y) {
        if (!ign) this.error('Do not have that key.')
        return
      }

      var sessKeys = this.sessKeys[our_keyid][their_keyid]

      var ctr = HLP.unpackCtr(msg[4])
      if (ctr <= sessKeys.rcv_counter) {
        if (!ign) this.error('Counter in message is not larger.')
        return
      }
      sessKeys.rcv_counter = ctr

      // verify mac
      vt += msg.slice(0, 6).join('')
      var vmac = HLP.make1Mac(vt, sessKeys.rcvmac)

      if (msg[6] !== vmac) {
        if (!ign) this.error('MACs do not match.')
        return
      }
      sessKeys.rcvmacused = true

      var out = HLP.decryptAes(
          msg[5].substring(4)
        , sessKeys.rcvenc
        , HLP.padCtr(msg[4])
      )

      if (!our_keyid) this.rotateOurKeys()
      if (!their_keyid) this.rotateTheirKeys(HLP.readMPI(msg[3]))

      // parse TLVs
      var ind = out.indexOf('\x00')
      if (~ind) {
        this.handleTLVs(out.substring(ind + 1))
        out = out.substring(0, ind)
      }

      return out
    },

    handleTLVs: function (tlvs) {
      var type, len, msg
      for (; tlvs.length; ) {
        type = HLP.unpackSHORT(tlvs.substr(0, 2))
        len = HLP.unpackSHORT(tlvs.substr(2, 2))

        // TODO: handle pathological cases better
        if (!len || (len + 4) > tlvs.length) break

        msg = tlvs.substr(4, len)

        // SMP
        if (type > 1 && type < 7)
          this.sm.handleSM({ msg: msg, type: type })

        tlvs = tlvs.substring(4 + len)
      }
    },

    sendQueryMsg: function (ecb) {
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

      this.sendMsg(msg, null, true)
    },

    sendMsg: function (msg, cb, internal) {
      if (internal) return this.iocb(msg)  // a user or sm msg

      switch (this.msgstate) {
        case STATES.MSGSTATE_PLAINTEXT:
          if (this.REQUIRE_ENCRYPTION) {
            this.storedMgs.push({str: msg, cb: cb})
            this.sendQueryMsg()
            return
          }
          if (this.SEND_WHITESPACE_TAG) {
            // and haven't received a PT msg since entering PT
            // msg += whitespace_tag
          }
          break
        case STATES.MSGSTATE_FINISHED:
          this.storedMgs.push({str: msg, cb: cb})
          this.error('Message cannot be sent at this time.')
          return
        default:
          this.storedMgs.push({str: msg, cb: cb})
          var otr = this
          this.prepareMsg(msg, function (err, msg, final) {
            if (err) return otr.error(err)
            otr.iocb(msg)
            if(final && typeof cb == "function") cb()
          })
          return
      }
    },

    receiveMsg: function (msg) {

      // parse type
      msg = ParseOTR.parseMsg(this, msg)

      if (!msg) return

      switch (msg.cls) {
        case 'error':
          this.error(msg.msg)
          return
        case 'ake':
          this.ake.handleAKE(msg)
          return
        case 'data':
          msg.msg = this.handleDataMsg(msg)
          break
      }

      if (msg.msg) this.uicb(msg.msg)
    },

    error: function (err, send) {
      if (send) {
        err = '?OTR Error:' + err
        this.sendMsg(err, null, true)
        return
      }
      // should cb be a node style function (err, msg) {}
      // or just instanceof Error ?
      this.uicb(err)
    },

    sendStored: function () {
      var self = this
      ;(this.storedMgs.splice(0)).forEach(function (msg) {
        self.sendMsg(msg.str, msg.cb)
      })
    },

    endOtr: function () {
      if (this.msgstate === STATES.MSGSTATE_ENCRYPTED) {
        this.sendMsg('\x00\x01\x00\x00')
        this.sm = null
      }
      this.msgstate = STATES.MSGSTATE_PLAINTEXT
    }

  }

  var emitter_prototype = EventEmitter.extend()
  for(i in emitter_prototype){
    OTR.prototype[i] = emitter_prototype[i]
  }

}).call(this)
