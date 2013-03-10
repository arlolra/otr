;(function () {
  "use strict"

  var root = this

  var CryptoJS, BigInt, EventEmitter, CONST, HLP, Parse, AKE, SM, DSA
  if (typeof exports !== 'undefined') {
    module.exports = OTR
    CryptoJS = require('../vendor/crypto.js')
    BigInt = require('../vendor/bigint.js')
    EventEmitter = require('../vendor/eventemitter.js').EventEmitter
    CONST = require('./const.js')
    HLP = require('./helpers.js')
    Parse = require('./parse.js')
    AKE = require('./ake.js')
    SM = require('./sm.js')
    DSA = require('./dsa.js')
    // expose CONST for consistency with docs
    OTR.CONST = CONST
  } else {
    // copy over and expose internals
    Object.keys(root.OTR).forEach(function (k) {
      OTR[k] = root.OTR[k]
    })
    root.OTR = OTR
    CryptoJS = root.CryptoJS
    BigInt = root.BigInt
    EventEmitter = root.EventEmitter
    CONST = OTR.CONST
    HLP = OTR.HLP
    Parse = OTR.Parse
    AKE = OTR.AKE
    SM = OTR.SM
    DSA = root.DSA
  }

  // diffie-hellman modulus and generator
  // see group 5, RFC 3526
  var G = BigInt.str2bigInt(CONST.G, 10)
  var N = BigInt.str2bigInt(CONST.N, 16)

  // OTR contructor
  function OTR(options) {
    if (!(this instanceof OTR)) return new OTR(options)

    // options
    options = options || {}

    // private keys
    if (options.priv && !(options.priv instanceof DSA))
      throw new Error('Requires long-lived DSA key.')

    this.priv = options.priv ? options.priv : new DSA()

    this.fragment_size = options.fragment_size || 0
    if (!(this.fragment_size >= 0))
      throw new Error('Fragment size must be a positive integer.')

    this.send_interval = options.send_interval || 0
    if (!(this.send_interval >= 0))
      throw new Error('Send interval must be a positive integer.')

    this.outgoing = []

    // instance tag
    this.our_instance_tag = options.instance_tag || OTR.makeInstanceTag()

    // debug
    this.debug = !!options.debug

    // init vals
    this.init()

    // bind methods
    var self = this
    ;['sendMsg', 'receiveMsg'].forEach(function (meth) {
      self[meth] = self[meth].bind(self)
    })

    EventEmitter.call(this)
  }

  // inherit from EE
  HLP.extend(OTR, EventEmitter)

  // add to prototype
  OTR.prototype.init = function () {

    this.msgstate = CONST.MSGSTATE_PLAINTEXT
    this.authstate = CONST.AUTHSTATE_NONE

    this.ALLOW_V2 = true
    this.ALLOW_V3 = true

    this.REQUIRE_ENCRYPTION = false
    this.SEND_WHITESPACE_TAG = false
    this.WHITESPACE_START_AKE = false
    this.ERROR_START_AKE = false

    Parse.initFragment(this)

    // their keys
    this.their_y = null
    this.their_old_y = null
    this.their_keyid = 0
    this.their_priv_pk = null
    this.their_instance_tag = '\x00\x00\x00\x00'

    // our keys
    this.our_dh = this.dh()
    this.our_old_dh = this.dh()
    this.our_keyid = 2

    // session keys
    this.sessKeys = [ new Array(2), new Array(2) ]

    // saved
    this.storedMgs = []
    this.oldMacKeys = []

    // smp
    this.sm = null  // initialized after AKE
    this.trust = false  // will be true after successful smp

    // when ake is complete
    // save their keys and the session
    this._akeInit()

    // receive plaintext message since switching to plaintext
    // used to decide when to stop sending pt tags when SEND_WHITESPACE_TAG
    this.receivedPlaintext = false

  }

  OTR.prototype._akeInit = function () {
    this.ake = new AKE(this)
    this.transmittedRS = false
    this.ssid = null
  }

  OTR.prototype._smInit = function () {
    this.sm = new SM(this)
  }

  OTR.prototype.io = function (msg) {

    // buffer
    this.outgoing = this.outgoing.concat(msg)

    var self = this
    ;(function send(first) {
      if (!first) {
        if (!self.outgoing.length) return
        var msg = self.outgoing.shift()
        self.trigger('io', [msg])
      }
      setTimeout(send, self.send_interval)
    }(true))

  }

  OTR.prototype.dh = function dh() {
    var keys = { privateKey: BigInt.randBigInt(320) }
    keys.publicKey = BigInt.powMod(G, keys.privateKey, N)
    return keys
  }

  // session constructor
  OTR.prototype.dhSession = function dhSession(our_dh, their_y) {
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

    // extra symmetric key
    this.extra_symkey = HLP.h2('\xff', secbytes)

    // counters
    this.send_counter = 0
    this.rcv_counter = 0
  }

  OTR.prototype.rotateOurKeys = function () {

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

  }

  OTR.prototype.rotateTheirKeys = function (their_y) {

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

  }

  OTR.prototype.prepareMsg = function (msg) {
    if (this.msgstate !== CONST.MSGSTATE_ENCRYPTED || this.their_keyid === 0)
      return this.error('Not ready to encrypt.')

    var sessKeys = this.sessKeys[1][0]
    sessKeys.send_counter += 1

    var ctr = HLP.packCtr(sessKeys.send_counter)

    var send = this.ake.otr_version + '\x03'  // version and type
    var v3 = (this.ake.otr_version === CONST.OTR_VERSION_3)

    if (v3) {
      send += this.our_instance_tag
      send += this.their_instance_tag
    }

    send += '\x00'  // flag
    send += HLP.packINT(this.our_keyid - 1)
    send += HLP.packINT(this.their_keyid)
    send += HLP.packMPI(this.our_dh.publicKey)
    send += ctr.substring(0, 8)

    var aes = HLP.encryptAes(
        CryptoJS.enc.Latin1.parse(msg)
      , sessKeys.sendenc
      , ctr
    )

    send += HLP.packData(aes)
    send += HLP.make1Mac(send, sessKeys.sendmac)
    send += HLP.packData(this.oldMacKeys.splice(0).join(''))

    sessKeys.sendmacused = true

    send = HLP.wrapMsg(
        send
      , this.fragment_size
      , v3
      , this.our_instance_tag
      , this.their_instance_tag
    )
    if (send[0]) return this.error(send[0])
    return send[1]
  }

  OTR.prototype.handleDataMsg = function (msg) {
    var vt = msg.version + msg.type

    if (this.ake.otr_version === CONST.OTR_VERSION_3)
      vt += msg.instance_tags

    var types = ['BYTE', 'INT', 'INT', 'MPI', 'CTR', 'DATA', 'MAC', 'DATA']
    msg = HLP.splitype(types, msg.msg)

    // ignore flag
    var ign = (msg[0] === '\x01')

    if (this.msgstate !== CONST.MSGSTATE_ENCRYPTED || msg.length !== 8) {
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
    out = out.toString(CryptoJS.enc.Latin1)

    if (!our_keyid) this.rotateOurKeys()
    if (!their_keyid) this.rotateTheirKeys(HLP.readMPI(msg[3]))

    // parse TLVs
    var ind = out.indexOf('\x00')
    if (~ind) {
      this.handleTLVs(out.substring(ind + 1), sessKeys)
      out = out.substring(0, ind)
    }

    out = CryptoJS.enc.Latin1.parse(out)
    return out.toString(CryptoJS.enc.Utf8)
  }

  OTR.prototype.handleTLVs = function (tlvs, sessKeys) {
    var type, len, msg
    for (; tlvs.length; ) {
      type = HLP.unpackSHORT(tlvs.substr(0, 2))
      len = HLP.unpackSHORT(tlvs.substr(2, 2))

      msg = tlvs.substr(4, len)

      // TODO: handle pathological cases better
      if (msg.length < len) break

      switch (type) {
        case 1:
          // Disconnected
          this.msgstate = CONST.MSGSTATE_FINISHED
          this.trigger('status', [CONST.STATUS_END_OTR])
          break
        case 2: case 3: case 4:
        case 5: case 6: case 7:
          // SMP
          this.sm.handleSM({ msg: msg, type: type })
          break
        case 8:
          // Extra Symkey
          // sessKeys.extra_symkey
          break
      }

      tlvs = tlvs.substring(4 + len)
    }
  }

  OTR.prototype.smpSecret = function (secret, question) {
    if (this.msgstate !== CONST.MSGSTATE_ENCRYPTED)
      return this.error('Must be encrypted for SMP.')

    if (typeof secret !== 'string' || secret.length < 1)
      return this.error('Secret is required.')

    this.sm.rcvSecret(secret, question)
  }

  OTR.prototype.sendQueryMsg = function () {
    var versions = {}
      , msg = CONST.OTR_TAG

    if (this.ALLOW_V2) versions['2'] = true
    if (this.ALLOW_V3) versions['3'] = true

    // but we don't allow v1
    // if (versions['1']) msg += '?'

    var vs = Object.keys(versions)
    if (vs.length) {
      msg += 'v'
      vs.forEach(function (v) {
        if (v !== '1') msg += v
      })
      msg += '?'
    }

    this._sendMsg(msg, true)
    this.trigger('status', [CONST.STATUS_SEND_QUERY])
  }

  OTR.prototype.sendMsg = function (msg) {
    if ( this.REQUIRE_ENCRYPTION ||
         this.msgstate !== CONST.MSGSTATE_PLAINTEXT
    ) {
      msg = CryptoJS.enc.Utf8.parse(msg)
      msg = msg.toString(CryptoJS.enc.Latin1)
    }
    this._sendMsg(msg)
  }

  OTR.prototype._sendMsg = function (msg, internal) {
    if (!internal) {  // a user or sm msg

      switch (this.msgstate) {
        case CONST.MSGSTATE_PLAINTEXT:
          if (this.REQUIRE_ENCRYPTION) {
            this.storedMgs.push(msg)
            this.sendQueryMsg()
            return
          }
          if (this.SEND_WHITESPACE_TAG && !this.receivedPlaintext) {
            msg += CONST.WHITESPACE_TAG  // 16 byte tag
            if (this.ALLOW_V3) msg += CONST.WHITESPACE_TAG_V3
            if (this.ALLOW_V2) msg += CONST.WHITESPACE_TAG_V2
          }
          break
        case CONST.MSGSTATE_FINISHED:
          this.storedMgs.push(msg)
          this.error('Message cannot be sent at this time.')
          return
        default:
          msg = this.prepareMsg(msg)
      }

    }
    if (msg) this.io(msg)
  }

  OTR.prototype.receiveMsg = function (msg) {

    // parse type
    msg = Parse.parseMsg(this, msg)

    if (!msg) return

    switch (msg.cls) {
      case 'error':
        this.error(msg.msg)
        return
      case 'ake':
        if ( msg.version === CONST.OTR_VERSION_3 &&
          this.checkInstanceTags(msg.instance_tags)
        ) return  // ignore
        this.ake.handleAKE(msg)
        return
      case 'data':
        if ( msg.version === CONST.OTR_VERSION_3 &&
          this.checkInstanceTags(msg.instance_tags)
        ) return  // ignore
        msg.msg = this.handleDataMsg(msg)
        break
      case 'query':
        if (this.msgstate === CONST.MSGSTATE_ENCRYPTED) this._akeInit()
        this.doAKE(msg)
        break
      default:
        // check for encrypted
        if ( this.REQUIRE_ENCRYPTION ||
             this.msgstate !== CONST.MSGSTATE_PLAINTEXT
        ) this.error('Received an unencrypted message.')

        // received a plaintext message
        // stop sending the whitespace tag
        this.receivedPlaintext = true

        // received a whitespace tag
        if (this.WHITESPACE_START_AKE) this.doAKE(msg)
    }

    if (msg.msg) this.trigger('ui', [msg.msg])
  }

  OTR.prototype.checkInstanceTags = function (it) {
    var their_it = HLP.readLen(it.substr(0, 4))
    var our_it = HLP.readLen(it.substr(4, 4))

    if (our_it && our_it !== HLP.readLen(this.our_instance_tag))
      return true

    if (HLP.readLen(this.their_instance_tag)) {
      if (HLP.readLen(this.their_instance_tag) !== their_it) return true
    } else {
      if (their_it < 100) return true
      this.their_instance_tag = HLP.packINT(their_it)
    }
  }

  OTR.prototype.doAKE = function (msg) {
    if (this.ALLOW_V3 && ~msg.ver.indexOf(CONST.OTR_VERSION_3)) {
      this.ake.initiateAKE(CONST.OTR_VERSION_3)
    } else if (this.ALLOW_V2 && ~msg.ver.indexOf(CONST.OTR_VERSION_2)) {
      this.ake.initiateAKE(CONST.OTR_VERSION_2)
    } else {
      // is this an error?
      this.error('OTR conversation requested, ' +
        'but no compatible protocol version found.')
    }
  }

  OTR.prototype.error = function (err, send) {
    if (send) {
      if (!this.debug) err = "An OTR error has occurred."
      err = '?OTR Error:' + err
      this._sendMsg(err, true)
      return
    }
    this.trigger('error', [err])
  }

  OTR.prototype.sendStored = function () {
    var self = this
    ;(this.storedMgs.splice(0)).forEach(function (msg) {
      self._sendMsg(msg)
    })
  }

  OTR.prototype.endOtr = function () {
    if (this.msgstate === CONST.MSGSTATE_ENCRYPTED) {
      this.sendMsg('\x00\x00\x01\x00\x00')
      this.sm = null
    }
    this.msgstate = CONST.MSGSTATE_PLAINTEXT
    this.receivedPlaintext = false
    this.trigger('status', [CONST.STATUS_END_OTR])
  }

  // attach methods

  OTR.makeInstanceTag = function () {
    var num = BigInt.randBigInt(32)
    if (BigInt.greater(BigInt.str2bigInt('100', 16), num))
      return OTR.makeInstanceTag()
    return HLP.packINT(parseInt(BigInt.bigInt2str(num, 10), 10))
  }

}).call(this)