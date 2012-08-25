;(function () {

  var root = this

  var ParseOTR
  if (typeof exports !== 'undefined') {
    ParseOTR = exports
  } else {
    ParseOTR = root.ParseOTR = {}
  }

  var CryptoJS = root.CryptoJS
    , HLP = root.HLP
    , STATES = root.STATES

  if (typeof require !== 'undefined') {
    CryptoJS || (CryptoJS = require('../vendor/cryptojs/cryptojs.js'))
    HLP || (HLP = require('./helpers.js'))
    STATES || (STATES = require('./states.js'))
  }

  ParseOTR.parseMsg = function (otr, msg) {

    // is this otr?
    var start = msg.indexOf(STATES.OTR_TAG)
    if (!~start) {

      // restart fragments
      this.initFragment(otr)

      // whitespace tags
      var ver = []
      ind = msg.indexOf(STATES.WHITESPACE_TAG)

      if (~ind) {

        msg = msg.split('')
        msg.splice(ind, 16)

        var len = msg.length
        for (; ind < len;) {
          if (msg.slice(ind, ind + 8).join('') === STATES.WHITESPACE_TAG_V2) {
            msg.splice(ind, 8)
            ver.push(STATES.OTR_VERSION_2)
            break
          }
          ind += 8
        }

        msg = msg.join('')

      }

      return { msg: msg, ver: ver }
    }

    var ind = start + STATES.OTR_TAG.length
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
        return { cls: 'query', version: '2' }
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
      if (!otr['ALLOW_V' + HLP.unpackSHORT(version)]) return { msg: msg }

      ind += 4

      var end = msg.substring(ind).indexOf('.')
      if (!~end) return { msg: msg }

      msg = CryptoJS.enc.Base64.parse(msg.substring(ind, ind + end))
      msg = CryptoJS.enc.Latin1.stringify(msg)

      var cls
      if (~['\x02', '\x0a', '\x11', '\x12'].indexOf(type)) {
        cls = 'ake'
      } else if (type === '\x03') {
        cls = 'data'
      }

      return {
          version: version
        , type: type
        , msg: msg
        , cls: cls
      }
    }

    // error message
    if (msg.substring(ind, ind + 7) === ' Error:') {
      if (otr.ERROR_START_AKE) {
        otr.sendQueryMsg()
      }
      return { msg: msg.substring(ind + 7), cls: 'error' }
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