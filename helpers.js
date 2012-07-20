var CryptoJS = require('./vendor/sha256.js')
  , BigInt = require('./vendor/bigint.js')

module.exports = exports = {}

exports.divMod = function divMod(num, den, n) {
  return BigInt.multMod(num, BigInt.inverseMod(den, n), n)
}

exports.subMod = function subMod(one, two, n) {
  one = BigInt.mod(one, n)
  two = BigInt.mod(two, n)
  if (BigInt.greater(two, one)) one = BigInt.add(one, n)
  return BigInt.sub(one, two)
}

exports.randomExponent = function randomExponent() {
  return BigInt.randBigInt(1536)
}

exports.randomValue = function randomValue() {
  return BigInt.randBigInt(128)
}

exports.smpHash = function smpHash(version, fmpi, smpi) {
  var sha256 = CryptoJS.algo.SHA256.create()
  sha256.update(version.toString())
  sha256.update(BigInt.bigInt2str(fmpi, 10))
  if (smpi) sha256.update(BigInt.bigInt2str(smpi, 10))
  var hash = sha256.finalize()
  return BigInt.str2bigInt(hash.toString(CryptoJS.enc.Hex), 16)
}

exports.multPowMod = function multPowMod(a, b, c, d, e) {
  return BigInt.multMod(BigInt.powMod(a, b, e), BigInt.powMod(c, d, e), e)
}

exports.ZKP = function ZKP(v, c, d, e) {
  return BigInt.equals(c, exports.smpHash(v, d, e))
}

// greater than, or equal
exports.GTOE = function GTOE(a, b) {
  return (BigInt.equals(a, b) || BigInt.greater(a, b))
}

exports.h2 = function h2(b, secbytes) {
  var sha256 = CryptoJS.algo.SHA256.create()
  sha256.update(b)
  sha256.update(secbytes)
  var hash = sha256.finalize()
  return hash.toString(CryptoJS.enc.Latin1)
}

exports.mask = function mask(n) {
  return Math.pow(2, n)
}

exports.pack = function pack(d) {
  // big-endian, unsigned long
  var res = ''
  res += _toString(d >> 24 & 0xFF)
  res += _toString(d >> 16 & 0xFF)
  res += _toString(d >> 8 & 0xFF)
  res += _toString(d & 0xFF)
  return res
}

exports.packData = function packData(d) {
  return exports.pack(d.length) + d
}

exports.bigInt2bits = function bitInt2bits(bi) {
  var ba = ''
  while (!BigInt.isZero(mpi)) {
    ba = _num2bin[mpi[0] & 0xff] + ba
    BigInt.rightShift_(mpi, 8)
  }
  return ba
}

exports.packMPI = function packMPI(mpi) {
  return exports.packData(exports.bitInt2bits(mpi))
}

exports.readData = function readData(data) {
  data = exports.toByteArray(data)
  var n = (data.splice(0, 4)).reduce(function (p, n) {
    p <<= 8; return p | n
  }, 0)
  return [n, data]
}

exports.readMPI = function readMPI(data) {
  data = exports.readData(data)
  var mpi = BigInt.str2bigInt('0', 10, data[0])
  data[1].forEach(function (d, i) {
    if (i) BigInt.leftShift_(mpi, 8)
    mpi[0] |= d
  })
  return mpi
}

// https://github.com/msgpack/msgpack-javascript/blob/master/msgpack.js

var _bin2num = {}
  , _num2bin = {}
  , _toString = String.fromCharCode
  , _num2b64 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                "abcdefghijklmnopqrstuvwxyz0123456789+/").split("")
  , globalScope = this  // meh

;(function() {
    var i = 0, v;

    for (; i < 0x100; ++i) {
        v = _toString(i);
        _bin2num[v] = i; // "\00" -> 0x00
        _num2bin[i] = v; //     0 -> "\00"
    }
    // http://twitter.com/edvakf/statuses/15576483807
    for (i = 0x80; i < 0x100; ++i) { // [Webkit][Gecko]
        _bin2num[_toString(0xf700 + i)] = i; // "\f780" -> 0x80
    }
})();

exports.toByteArray = function toByteArray(data) {
    var rv = [], bin2num = _bin2num, remain,
        ary = data.split(""),
        i = -1, iz;

    iz = ary.length;
    remain = iz % 8;

    while (remain--) {
        ++i;
        rv[i] = bin2num[ary[i]];
    }
    remain = iz >> 3;
    while (remain--) {
        rv.push(bin2num[ary[++i]], bin2num[ary[++i]],
                bin2num[ary[++i]], bin2num[ary[++i]],
                bin2num[ary[++i]], bin2num[ary[++i]],
                bin2num[ary[++i]], bin2num[ary[++i]]);
    }
    return rv;
}

exports.base64encode = function base64encode(data) {
    var rv = [],
        c = 0, i = -1, iz = data.length,
        pad = [0, 2, 1][data.length % 3],
        num2bin = _num2bin,
        num2b64 = _num2b64;

    if (globalScope.btoa) {
        while (i < iz) {
            rv.push(num2bin[data[++i]]);
        }
        return btoa(rv.join(""));
    }
    --iz;
    while (i < iz) {
        c = (data[++i] << 16) | (data[++i] << 8) | (data[++i]); // 24bit
        rv.push(num2b64[(c >> 18) & 0x3f],
                num2b64[(c >> 12) & 0x3f],
                num2b64[(c >>  6) & 0x3f],
                num2b64[ c        & 0x3f]);
    }
    pad > 1 && (rv[rv.length - 2] = "=");
    pad > 0 && (rv[rv.length - 1] = "=");
    return rv.join("");
}