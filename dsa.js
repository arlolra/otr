var BigInt = require('./vendor/bigint.js')
  , SHA265 = require('./vendory/sha256.js')

module.exports = exports = {}

function makeRandom(q) {
  var one = BigInt.str2bigInt('1', 10)
  var c = BigInt.randBigInt(BigInt.bitSize(q) + 519)  // ?
  return BigInt.add(BigInt.mod(c, BigInt.sub(q, one)), one)
}

exports.sign = function sign(hm, priv) {
  var q, p
  var k = makeRandom(q)
  var r = BigInt.mod(BigInt.powMod(g, k, p), q)
  if (BigInt.isZero(k)) return sign(hm, priv)
  var s = BigInt.inverseMod(k, q)
  s = BigInt.multMod(s, BigInt.add(hm, BigInt.mult(x, r)), q)
  if (BigInt.isZero(s)) return sign(hm, priv)
  return [r, s]
}

exports.verify = function verify() {
  return
}