;(function () {

  var root = this

  var HLP
  if (typeof exports !== 'undefined') {
    HLP = exports
  } else {
    HLP = root.HLP = {}
  }

  var BigInt = root.BigInt
    , CryptoJS = root.CryptoJS

  if (typeof require !== 'undefined') {
    BigInt || (BigInt = require('./vendor/bigint.js'))
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
  }

  HLP.divMod = function divMod(num, den, n) {
    return BigInt.multMod(num, BigInt.inverseMod(den, n), n)
  }

  HLP.subMod = function subMod(one, two, n) {
    one = BigInt.mod(one, n)
    two = BigInt.mod(two, n)
    if (BigInt.greater(two, one)) one = BigInt.add(one, n)
    return BigInt.sub(one, two)
  }

  HLP.randomExponent = function randomExponent() {
    return BigInt.randBigInt(1536)
  }

  HLP.randomValue = function randomValue() {
    return BigInt.randBigInt(128)
  }

  HLP.smpHash = function smpHash(version, fmpi, smpi) {
    var sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(version.toString())
    sha256.update(BigInt.bigInt2str(fmpi, 10))
    if (smpi) sha256.update(BigInt.bigInt2str(smpi, 10))
    var hash = sha256.finalize()
    return BigInt.str2bigInt(hash.toString(CryptoJS.enc.Hex), 16)
  }

  HLP.makeMac = function makeMac(aesctr, m) {
    var pass = CryptoJS.enc.Latin1.parse(m)
    var mac = CryptoJS.HmacSHA256(aesctr, pass)
    return HLP.mask(mac.toString(CryptoJS.enc.Latin1), 0, 160)
  }

  HLP.makeAes = function makeAes(msg, c, iv) {
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

  HLP.decryptAes = function decryptAes(msg, c, iv) {
    msg = CryptoJS.enc.Latin1.parse(msg)
    var opts = {
        mode: CryptoJS.mode.CTR
      , iv: CryptoJS.enc.Latin1.parse(iv)
      , padding: CryptoJS.pad.NoPadding
    }
    var aesctr = CryptoJS.AES.decrypt(
        CryptoJS.enc.Base64.stringify(msg)
      , CryptoJS.enc.Latin1.parse(c)
      , opts
    )
    return aesctr.toString(CryptoJS.enc.Latin1)
  }

  HLP.multPowMod = function multPowMod(a, b, c, d, e) {
    return BigInt.multMod(BigInt.powMod(a, b, e), BigInt.powMod(c, d, e), e)
  }

  HLP.ZKP = function ZKP(v, c, d, e) {
    return BigInt.equals(c, HLP.smpHash(v, d, e))
  }

  // greater than, or equal
  HLP.GTOE = function GTOE(a, b) {
    return (BigInt.equals(a, b) || BigInt.greater(a, b))
  }

  HLP.between = function between(x, a, b) {
    return (BigInt.greater(x, a) && BigInt.greater(b, x))
  }

  var OPS = {
      'XOR': function (c, s) { return c ^ s }
    , 'OR': function (c, s) { return c | s }
    , 'AND': function (c, s) { return c & s }
  }
  HLP.bigBitWise = function bigBitWise(op, a, b) {
    var tf = (a.length > b.length)
      , short = tf ? b : a
      , long  = tf ? a : b
      , len = long.length
      , c = BigInt.expand(short, len)
      , i = 0
    for (; i < len; i++) {
      c[i] = OPS[op](c[i], long[i])
    }
    return c
  }

  HLP.h1 = function h1(b, secbytes) {
    return (CryptoJS.SHA1(b + secbytes)).toString(CryptoJS.enc.Latin1)
  }

  HLP.h2 = function h2(b, secbytes) {
    var sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(b)
    sha256.update(secbytes)
    var hash = sha256.finalize()
    return hash.toString(CryptoJS.enc.Latin1)
  }

  HLP.mask = function mask(bytes, start, n) {
    start = start / 8
    return bytes.substring(start + 0, start + (n / 8))
  }

  HLP.twotothe = function twotothe(g) {
    var ex = g % 4
    g = Math.floor(g / 4)
    var str = (Math.pow(2, ex)).toString()
    for (var i = 0; i < g; i++) str += '0'
    return BigInt.str2bigInt(str, 16)
  }

  HLP.pack = function pack(d) {
    // big-endian, unsigned long
    var res = ''
    res += _toString(d >> 24 & 0xFF)
    res += _toString(d >> 16 & 0xFF)
    res += _toString(d >> 8 & 0xFF)
    res += _toString(d & 0xFF)
    return res
  }

  HLP.unpack = function (arr) {
    return arr.reduce(function (p, n) {
      return (p << 8) | n
    }, 0)
  }

  HLP.packData = function packData(d) {
    return HLP.pack(d.length) + d
  }

  HLP.unpackData = function unpackData(d) {
    return d.substring(4)
  }

  HLP.bigInt2bits = function bitInt2bits(bi) {
    bi = BigInt.dup(bi)
    var ba = ''
    while (!BigInt.isZero(bi)) {
      ba = _num2bin[bi[0] & 0xff] + ba
      BigInt.rightShift_(bi, 8)
    }
    return ba
  }

  HLP.bits2bigInt = function (bits) {
    bits = HLP.toByteArray(bits)
    return HLP.retMPI(bits)
  }

  HLP.packMPI = function packMPI(mpi) {
    return HLP.packData(HLP.bigInt2bits(BigInt.trim(mpi, 0)))
  }

  HLP.readLen = function (msg) {
    msg = HLP.toByteArray(msg)
    return HLP.unpack(msg.slice(0, 4))
  }

  HLP.readData = function readData(data) {
    var n = HLP.unpack(data.splice(0, 4))
    return [n, data]
  }

  HLP.retMPI = function retMPI(data) {
    var mpi = BigInt.str2bigInt('0', 10, data.length)
    data.forEach(function (d, i) {
      if (i) BigInt.leftShift_(mpi, 8)
      mpi[0] |= d
    })
    return mpi
  }

  HLP.readMPI = function readMPI(data) {
    data = HLP.toByteArray(data)
    data = HLP.readData(data)
    return HLP.retMPI(data[1])
  }

  HLP.parseStr = function parseStr(str) {
    var s = []
    str = HLP.toByteArray(str)
    while (str.length) {
      str = HLP.readData(str)
      s.push(str[1].splice(0, str[0]))
      str = str[1]
    }
    return s
  }

  HLP.parseToStrs = function parseToStrs(str) {
    var n, s = []
    while (str.length) {
      n = (HLP.readData(HLP.toByteArray(str.substring(0, 4))))[0] + 4
      s.push(str.substring(0, n))
      str = str.substring(n)
    }
    return s
  }

  // otr message wrapper begin and end
  var WRAPPER_BEGIN = "?OTR:"
  var WRAPPER_END = "."

  HLP.wrapMsg = function wrapMsg(msg) {
    msg = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(msg))
    return WRAPPER_BEGIN + msg + WRAPPER_END
  }

  HLP.splitype = function splitype(arr, msg) {
    var data = []

    // data types (byte lengths)
    var dts =  {
        BYTE: 1
      , SHORT: 2
      , INT: 4
      , CTR: 8
      , MAC: 20
      , SIG: 40
    }

    arr.forEach(function (a) {
      var len, str
      switch (a) {
        case 'PUBKEY':
          str = splitype(['SHORT', 'MPI', 'MPI', 'MPI', 'MPI'], msg).join('')
          break
        case 'DATA':  // falls through
        case 'MPI':
          str = msg.substring(0, HLP.readLen(msg) + 4)
          break
        default:
          str = msg.substring(0, dts[a])
      }
      data.push(str)
      msg = msg.substring(str.length)
    })

    return data
  }

  // https://github.com/msgpack/msgpack-javascript/blob/master/msgpack.js

  var _bin2num = {}
    , _num2bin = {}
    , _b642bin = {}
    , _toString = String.fromCharCode

  var i = 0, v

  for (; i < 0x100; ++i) {
    v = _toString(i)
    _bin2num[v] = i  // "\00" -> 0x00
    _num2bin[i] = v  //     0 -> "\00"
  }

  for (i = 0x80; i < 0x100; ++i) {  // [Webkit][Gecko]
    _bin2num[_toString(0xf700 + i)] = i  // "\f780" -> 0x80
  }

  HLP.toByteArray = function toByteArray(data) {
    var rv = [], bin2num = _bin2num, remain
      , ary = data.split("")
      , i = -1
      , iz

    iz = ary.length
    remain = iz % 8

    while (remain--) {
      ++i
      rv[i] = bin2num[ary[i]]
    }
    remain = iz >> 3
    while (remain--) {
      rv.push(bin2num[ary[++i]], bin2num[ary[++i]],
              bin2num[ary[++i]], bin2num[ary[++i]],
              bin2num[ary[++i]], bin2num[ary[++i]],
              bin2num[ary[++i]], bin2num[ary[++i]])
    }
    return rv
  }

}).call(this)