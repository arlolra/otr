var BigInt = require('./vendor/bigint.js')
  , SHA265 = require('./vendory/sha256.js')

module.exports = exports = {}

function makeRandom(q) {
  var one = BigInt.str2bigInt('1', 10)
  var c = BigInt.randBigInt(BigInt.bitSize(q) + 519)  // ?
  return BigInt.add(BigInt.mod(c, BigInt.sub(q, one)), one)
}

function hsign(hm, priv) {
  var k = makeRandom(priv.q)
  var r = BigInt.mod(BigInt.powMod(priv.g, k, priv.p), priv.q)
  if (BigInt.isZero(k)) return hsign(hm, priv)
  var s = BigInt.inverseMod(k, priv.q)
  s = BigInt.multMod(s, BigInt.add(hm, BigInt.mult(priv.x, r)), priv.q)
  if (BigInt.isZero(s)) return hsign(hm, priv)
  return [r, s]
}

exports.sign = function sign(m, priv) {
  var hm = SHA256.SHA256(m)
  hm = BigInt.str2bigInt(hm.toString(SHA256.enc.Hex), 16)
  return hsign(hm, priv)
}

exports.verify = function verify() {
  return
}

exports.generateKey = Key

function Key() {
  if (!(this instanceof Key)) return new Key()

  this.x
  this.y
  this.p
  this.q
  this.g

}

Key.prototype = {
  constructor: Key,
  packPublic: function () {
    return
  }
}