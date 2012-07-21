var BigInt = require('./vendor/bigint.js')
  , SHA265 = require('./vendor/sha256.js')
  , SHA1 = require('./vendor/sha1.js')
  , hlp = require('./helpers.js')

var ZERO = BigInt.str2bigInt('0', 10)
  , ONE = BigInt.str2bigInt('1', 10)
  , TWO = BigInt.str2bigInt('2', 10)

module.exports = exports = {}

function makeRandom(q) {
  var c = BigInt.randBigInt(BigInt.bitSize(q) + 519)  // ?
  return BigInt.add(BigInt.mod(c, BigInt.sub(q, ONE)), ONE)
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

exports.verify = function verify(hm, priv, r, s) {
  if (!hlp.between(s, ZERO, priv.q) || !hlp.between(s, ZERO, priv.q))
    return false

  var w = BigInt.inverseMod(s, q)
  var u1 = BigInt.multMod(hm, w, q)
  var u2 = BigInt.multMod(r, w, q)

  u1 = BigInt.powMod(priv.g, u1, p)
  u2 = BigInt.powMod(priv.y, u2, p)

  var v = BigInt.mod(BigInt.multMod(u1, u2, p), q)

  return BigInt.equal(v, r)
}

function pickBase(prime) {
  var b = BigInt.bitSize(prime)
  var base = BigInt.randBigInt(b)
  while (!BigInt.greater(prime, base))  // pick a random that's < ans
    base = BigInt.randBigInt(b)
  return base
}

function MR(prime) {
  var j = 0, k = true
  // 40x should give 2^80 confidence
  for (var j = 0; j < 40; j++) {
    if (!BigInt.millerRabin(prime, pickBase(prime))) {
      k = false
      break
    }
  }
  return k
}

exports.generateKey = Key

function Key() {
  if (!(this instanceof Key)) return new Key()

  this.N = 160
  this.L = 1024
  this.makePQ()

  // this.makeG()

  // this.x
  // this.y
}

Key.prototype = {

  constructor: Key,

  makePQ: function() {
    var g = this.N
    this.seed = BigInt.randBigInt(this.N)

    var u = (SHA1.SHA1(hlp.bigInt2bits(this.seed))).toString(SHA1.enc.Hex)
    var tmp = BigInt.mod(BigInt.add(this.seed, ONE), hlp.twotothe(g))
    tmp = (SHA1.SHA1(hlp.bigInt2bits(tmp))).toString(SHA1.enc.Hex)
    u = hlp.bigBitWise(
        'XOR'
      , BigInt.str2bigInt(tmp, 16)
      , BigInt.str2bigInt(u, 16)
    )

    this.q = hlp.bigBitWise('OR', u, hlp.twotothe(g - 1))
    this.q = hlp.bigBitWise('OR', this.q, ONE)

    if (!MR(this.q)) return this.makePQ()

    this.counter = 0
    this.step7(TWO)
  },

  step7: function step7(offset) {
    var g = this.N
    var n = Math.floor(this.L / this.N)
    var b = (this.L % this.N) - 1

    var V = ZERO
    var W = ZERO

    var cache_seed_plus_offset = BigInt.add(this.seed, offset)

    var i = 0
    for (; i < (n + 1); i++) {
      V = BigInt.add(
          cache_seed_plus_offset
        , BigInt.str2bigInt(i.toString(), 10)
      )
      V = SHA1.SHA1(hlp.bigInt2bits(BigInt.mod(V, hlp.twotothe(g))))
      V = BigInt.str2bigInt(V.toString(SHA1.enc.Hex), 16)
      if (i === n) V = BigInt.mod(V, hlp.twotothe(b))
      V = BigInt.mult(V, hlp.twotothe(g * i))
      W = BigInt.add(W, V)
    }

    var Lminus = hlp.twotothe(this.L - 1)
    var X = BigInt.add(W, Lminus)
    // console.log(hlp.between(X, Lminus, hlp.twotothe(this.L)))

    var c = BigInt.mod(X, BigInt.mult(TWO, this.q))
    this.p = BigInt.sub(X, BigInt.sub(c, ONE))

    if (!BigInt.greater(Lminus, this.p)) {
      // test the primality of p
      if (MR(this.p)) return
    }

    offset = BigInt.add(offset, BigInt.str2bigInt((n + 1).toString(), 10))
    this.counter += 1

    if (this.counter >= 4096) return this.makePQ()
    this.step7(offset)
  },

  makeG: function (e) {
    if (!e) e = BigInt.multMod(
        BigInt.sub(this.p, ONE)
      , BigInt.inverseMod(this.q, this.p)
      , this.p
    )
    var h
    this.g = BigInt.powMod(h, e, this.p)
    if (BigInt.equal(g, ONE)) this.makeG(e)
  },

  packPublic: function () {
    var str = '\x00\x00'
    str += hlp.packMPI(this.p)
    str += hlp.packMPI(this.q)
    str += hlp.packMPI(this.g)
    str += hlp.packMPI(this.y)
    return str
  }

}