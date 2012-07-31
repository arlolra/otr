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
  var OTR_VERSION_2 = '\x00\x02'

  ParseOTR.parseMsg = function (otr, msg) {

    // is this otr?
    var start = msg.indexOf(OTR_TAG)
    if (!~start) {
      // check for tags
      this.initFragment(otr)
      return msg
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

      if (qi < 1) return ''
      qs = qs.substring(0, qi).split('')

      if (msg[ind] === 'v') {
        qs.forEach(function (q) {
          otr.versions[q] = true
        })
      }

      return ''
    }

    // otr message
    if (com === ':') {

      var info = msg.substring(ind + 1, ind + 5)
      if (info.length < 4) return msg
      info = CryptoJS.enc.Base64.parse(info).toString(CryptoJS.enc.Latin1)

      var version = info.substring(0, 2)
      var type = info.substring(2)

      // only supporting otr version 2
      if (version !== OTR_VERSION_2) return msg

      var end = msg.substring(ind + 4).indexOf('.')
      if (!~end) return msg

      return this.handle(otr, version, type, msg.substring(ind + 4, end))
    }

    // error message
    if (msg.substring(ind, ind + 7) === ' Error:') {
      return new Error(msg.substring(ind + 7))
    }

    return msg
  }

  ParseOTR.handle = function (otr, version, type, msg) {
    return 'OTR'
  }

  ParseOTR.initFragment = function (otr) {
    otr.fragment = { s: '', j: 0, k: 0 }
  }

  ParseOTR.msgFragment = function (otr, msg) {
    msg = msg.split(',')

    if (msg.length < 4 ||
      isNaN(parseInt(msg[0], 10)) ||
      isNaN(parseInt(msg[1], 10))
    ) return ''

    var k = parseInt(msg[0], 10)
    var n = parseInt(msg[1], 10)
    msg = msg[2]

    if (n < k || n === 0 || k === 0) {
      this.initFragment(otr)
      return ''
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

    return ''
  }

}).call(this)