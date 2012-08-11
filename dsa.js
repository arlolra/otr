// DSA
// http://www.itl.nist.gov/fipspubs/fip186.htm

;(function () {

  var root = this

  var DSA
  if (typeof exports !== 'undefined') {
    DSA = exports
  } else {
    DSA = root.DSA = {}
  }

  var BigInt = root.BigInt
    , CryptoJS = root.CryptoJS
    , HLP = root.HLP

  if (typeof require !== 'undefined') {
    BigInt || (BigInt = require('./vendor/bigint.js'))
    CryptoJS || (CryptoJS = require('./vendor/cryptojs/cryptojs.js'))
    HLP || (HLP = require('./helpers.js'))
  }

  var ZERO = BigInt.str2bigInt('0', 10)
    , ONE = BigInt.str2bigInt('1', 10)
    , TWO = BigInt.str2bigInt('2', 10)

  function makeRandom(min, max) {
    var c = BigInt.randBigInt(BigInt.bitSize(max))
    if (!HLP.between(c, min, max)) return makeRandom(min, max)
    return c
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
    // 40x should give 2^-80 confidence
    for (; j < 40; j++) {
      if (!BigInt.millerRabin(prime, pickBase(prime))) {
        k = false
        break
      }
    }
    return k
  }

  DSA.Key = Key

  function Key() {
    if (!(this instanceof Key)) return new Key()

    this.N = 160
    this.L = 1024

    this.type = '\x00\x00'

    this.makePQ()
    this.makeG()

    this.x = makeRandom(ZERO, this.q)
    this.y = BigInt.powMod(this.g, this.x, this.p)
  }

  Key.prototype = {

    constructor: Key,

    makePQ: function() {
      var g = this.N
      this.seed = BigInt.randBigInt(this.N)

      var u = (CryptoJS.SHA1(HLP.bigInt2bits(this.seed))).toString(CryptoJS.enc.Hex)
      var tmp = BigInt.mod(BigInt.add(this.seed, ONE), HLP.twotothe(g))
      tmp = (CryptoJS.SHA1(HLP.bigInt2bits(tmp))).toString(CryptoJS.enc.Hex)
      u = HLP.bigBitWise(
          'XOR'
        , BigInt.str2bigInt(tmp, 16)
        , BigInt.str2bigInt(u, 16)
      )

      this.q = HLP.bigBitWise('OR', u, HLP.twotothe(g - 1))
      this.q = HLP.bigBitWise('OR', this.q, ONE)

      if (!MR(this.q)) return this.makePQ()

      this.counter = 0

      var n = Math.floor(this.L / this.N)
      var b = (this.L % this.N) - 1

      // var start = new Date()
      this.step7(TWO, this.N, n, b)
      // console.log(new Date() - start)
    },

    step7: function (offset, g, n, b) {
      var V = ZERO
      var W = ZERO

      var cache_seed_plus_offset = BigInt.add(this.seed, offset)

      var i = 0
      for (; i < (n + 1); i++) {
        V = BigInt.add(
            cache_seed_plus_offset
          , BigInt.str2bigInt(i.toString(), 10)
        )
        V = CryptoJS.SHA1(HLP.bigInt2bits(BigInt.mod(V, HLP.twotothe(g))))
        V = BigInt.str2bigInt(V.toString(CryptoJS.enc.Hex), 16)
        if (i === n) V = BigInt.mod(V, HLP.twotothe(b))
        V = BigInt.mult(V, HLP.twotothe(g * i))
        W = BigInt.add(W, V)
      }

      var Lminus = HLP.twotothe(this.L - 1)
      var X = BigInt.add(W, Lminus)
      // console.log(HLP.between(X, Lminus, HLP.twotothe(this.L)))

      var c = BigInt.mod(X, BigInt.mult(TWO, this.q))
      this.p = BigInt.sub(X, BigInt.sub(c, ONE))

      if (!BigInt.greater(Lminus, this.p)) {
        // test the primality of p
        if (MR(this.p)) return
      }

      offset = BigInt.add(offset, BigInt.str2bigInt((n + 1).toString(), 10))
      this.counter += 1

      if (this.counter >= 4096) return this.makePQ()
      this.step7(offset, g, n, b)
    },

    makeG: function (e) {
      var p_minus = BigInt.sub(this.p, ONE)
      if (!e) e = BigInt.multMod(
          p_minus
        , BigInt.inverseMod(this.q, this.p)
        , this.p
      )
      var h = TWO  // makeRandom(ONE, p_minus)
      this.g = BigInt.powMod(h, e, this.p)
      if (!BigInt.greater(this.g, ONE)) this.makeG(e)
    },

    packPublic: function () {
      var str = this.type
      str += HLP.packMPI(this.p)
      str += HLP.packMPI(this.q)
      str += HLP.packMPI(this.g)
      str += HLP.packMPI(this.y)
      return str
    },

    hsign: function (hm) {
      var k = makeRandom(ZERO, this.q)
      var r = BigInt.mod(BigInt.powMod(this.g, k, this.p), this.q)
      if (BigInt.isZero(r)) return this.hsign(hm)
      var s = BigInt.inverseMod(k, this.q)
      s = BigInt.mult(s, BigInt.add(hm, BigInt.mult(this.x, r)))
      s = BigInt.mod(s, this.q)
      if (BigInt.isZero(s)) return this.hsign(hm)
      return [r, s]
    },

    sign: function (m) {
      var hm = CryptoJS.enc.Latin1.parse(m)  // CryptoJS.SHA1(m)
      hm = BigInt.str2bigInt(hm.toString(CryptoJS.enc.Hex), 16)
      return this.hsign(hm)
    }

  }

  DSA.parsePublic = function (str) {
    str = HLP.splitype(['SHORT', 'MPI', 'MPI', 'MPI', 'MPI'], str)
    return {
        type: str[0]
      , p: HLP.readMPI(str[1])
      , q: HLP.readMPI(str[2])
      , g: HLP.readMPI(str[3])
      , y: HLP.readMPI(str[4])
    }
  }

  DSA.verify = function (key, m, r, s) {
    if (!HLP.between(r, ZERO, key.q) || !HLP.between(s, ZERO, key.q))
      return false

    var hm = CryptoJS.enc.Latin1.parse(m)  // CryptoJS.SHA1(m)
    hm = BigInt.str2bigInt(hm.toString(CryptoJS.enc.Hex), 16)

    var w = BigInt.inverseMod(s, key.q)
    var u1 = BigInt.multMod(hm, w, key.q)
    var u2 = BigInt.multMod(r, w, key.q)

    u1 = BigInt.powMod(key.g, u1, key.p)
    u2 = BigInt.powMod(key.y, u2, key.p)

    var v = BigInt.mod(BigInt.multMod(u1, u2, key.p), key.q)

    return BigInt.equals(v, r)
  }

  DSA.fingerprint = function (key) {
    var pk = key.packPublic()
    if (key.type === '\x00\x00')
      pk = pk.substring(2)
    return CryptoJS.SHA1(pk).toString(CryptoJS.enc.Hex)
  }

  DSA.inherit = function (key) {
    key.__proto__ = DSA.Key.prototype
    key.constructor = DSA.Key
    key.type = '\x00\x00'
  }

}).call(this)