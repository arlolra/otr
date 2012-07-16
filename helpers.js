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