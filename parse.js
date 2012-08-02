;(function () {

  var root = this

  var ParseOTR
  if (typeof exports !== 'undefined') {
    ParseOTR = exports
  } else {
    ParseOTR = root.ParseOTR = {}
  }

  var CryptoJS = root.CryptoJS

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
  }

  // tags
  var OTR_TAG = '?OTR'

  // otr versions
  var OTR_VERSION_1 = '\x00\x01'
    , OTR_VERSION_2 = '\x00\x02'

  // data types (byte lengths)
  var BYTE = 1
    , SHORT = 2
    , INT = 4
    , MPI = INT  // + LEN
    , DATA = INT  // + LEN
    , CTR = 8
    , MAC = 20
    , PUBKEY = SHORT + (4 * MPI)
    , SIG = 40  // 2 * priv.q.length

  ParseOTR.parseMsg = function (otr, msg) {

    // is this otr?
    var start = msg.indexOf(OTR_TAG)
    if (!~start) {
      // check for tags
      this.initFragment(otr)
      return { msg: msg }
    }

    var ind = start + OTR_TAG.length
    var com = msg[ind]

    // message fragment
    if (com === ',') {
      return this.msgFragment(otr, msg.substring(ind + 1))
    }

    this.initFragment(otr)

    // query message
    if (~['?', 'v'].indexOf(com)) {

      // version 1
      if (msg[ind] === '?') {
        otr.versions['1'] = true
        ind += 1
      }

      // other versions
      var qs = msg.substring(ind + 1)
      var qi = qs.indexOf('?')

      if (qi < 1) return
      qs = qs.substring(0, qi).split('')

      if (msg[ind] === 'v') {
        qs.forEach(function (q) {
          otr.versions[q] = true
        })
      }

      // start ake
      if (otr.ALLOW_V2 && otr.versions['2']) {
        otr.ake.initiateAKE()
      } else if (otr.ALLOW_V1 && otr.versions['1']) {
        // not yet
      }

      return
    }

    // otr message
    if (com === ':') {

      ind += 1

      var info = msg.substring(ind, ind + 4)
      if (info.length < 4) return { msg: msg }
      info = CryptoJS.enc.Base64.parse(info).toString(CryptoJS.enc.Latin1)

      var version = info.substring(0, 2)
      var type = info.substring(2)

      // only supporting otr version 2
      if (version !== OTR_VERSION_2) return { msg: msg }

      ind += 4

      var end = msg.substring(ind).indexOf('.')
      if (!~end) return { msg: msg }

      return {
          version: version
        , type: type
        , msg: msg.substring(ind, ind + end)
        , class: 'otr'
      }
    }

    // error message
    if (msg.substring(ind, ind + 7) === ' Error:') {
      if (otr.ERROR_START_AKE) {
        otr.sendQueryMsg()
      }
      return { msg: msg.substring(ind + 7), class: 'error' }
    }

    return { msg: msg }
  }

  ParseOTR.initFragment = function (otr) {
    otr.fragment = { s: '', j: 0, k: 0 }
  }

  ParseOTR.msgFragment = function (otr, msg) {
    msg = msg.split(',')

    if (msg.length < 4 ||
      isNaN(parseInt(msg[0], 10)) ||
      isNaN(parseInt(msg[1], 10))
    ) return

    var k = parseInt(msg[0], 10)
    var n = parseInt(msg[1], 10)
    msg = msg[2]

    if (n < k || n === 0 || k === 0) {
      this.initFragment(otr)
      return
    }

    if (k === 1) {
      this.initFragment(otr)
      otr.fragment = { k: 1, n: n, s: msg }
    } else if (n === otr.fragment.n && k === (otr.fragment.k + 1)) {
      otr.fragment.s += msg
      otr.fragment.k += 1
    } else {
      this.initFragment(otr)
    }

    if (n === k) {
      msg = otr.fragment.s
      this.initFragment(otr)
      return this.parseMsg(otr, msg)
    }

    return
  }

}).call(this)