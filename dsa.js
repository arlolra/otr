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

exports.generateKey = Key

function Key() {
  if (!(this instanceof Key)) return new Key()

  var N = 160
  var L = 1024

  this.makePQ(N, L)

  // this.makeG()

  // this.x
  // this.y
}

Key.prototype = {

  constructor: Key,

  makePQ: function(N, L) {
    var n = Math.floor(L / N)
    var b = (L % N) - 1

    var g = N
    var seed = BigInt.randBigInt(N)

    var u = (SHA1.SHA1(hlp.bigInt2bits(seed))).toString(SHA1.enc.Hex)
    var twotog = hlp.twotothe(g)
    var tmp = BigInt.mod(BigInt.add(seed, ONE), twotog)
    tmp = (SHA1.SHA1(hlp.bigInt2bits(tmp))).toString(SHA1.enc.Hex)
    u = hlp.bigBitWise(
        'XOR'
      , BigInt.str2bigInt(tmp, 16)
      , BigInt.str2bigInt(u, 16)
    )

    this.q = hlp.bigBitWise('OR', u, hlp.twotothe(g - 1))
    this.q = hlp.bigBitWise('OR', this.q, ONE)

    // test if q is prime!
    // if not, rinse and repeat

    var counter = 0
    var offset = TWO

    var V = new Array(n)

    var cache_seed_plus_offset = BigInt.add(seed, offset)

    var i = 0
    for (; i < n; i++) {
      V[i] = BigInt.add(
          cache_seed_plus_offset
        , BigInt.str2bigInt(i.toString(), 10)
      )
      V[i] = SHA1.SHA1(hlp.bigInt2bits(BigInt.mod(V[i], twotog)))
    }

    // console.log(V)

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