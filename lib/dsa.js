// DSA
// http://www.itl.nist.gov/fipspubs/fip186.htm

;(function () {

  var root = this

  var CryptoJS, BigInt, HLP
  if (typeof exports !== 'undefined') {
    module.exports = DSA
    CryptoJS = require('../vendor/crypto.js')
    BigInt = require('../vendor/bigint.js')
    HLP = require('./helpers.js')
  } else {
    // copy over and expose internals
    Object.keys(root.DSA).forEach(function (k) {
      DSA[k] = root.DSA[k]
    })
    root.DSA = DSA
    CryptoJS = root.CryptoJS
    BigInt = root.BigInt
    HLP = DSA.HLP
  }

  var ZERO = BigInt.str2bigInt('0', 10)
    , ONE = BigInt.str2bigInt('1', 10)
    , TWO = BigInt.str2bigInt('2', 10)
    , KEY_TYPE = '\x00\x00'

  var DEBUG = false
  function timer() {
    var start = (new Date()).getTime()
    return function (s) {
      if (!DEBUG || typeof console === 'undefined') return
      var t = (new Date()).getTime()
      console.log(s + ': ' + (t - start))
      start = t
    }
  }

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

  function MR(prime, repeat) {
    var j = 0, k = true
    for (; j < repeat; j++) {
      if (!BigInt.millerRabin(prime, pickBase(prime))) {
        k = false
        break
      }
    }
    return k
  }

  var bit_lengths = {
      '1024': { N: 160, repeat: 40 }  // 40x should give 2^-80 confidence
    , '2048': { N: 224, repeat: 56 }
    , '3072': { N: 256, repeat: 64 }
  }

  var primes = {}

  function generatePrimes(bit_length) {

    var t = timer()  // for debugging

    var N = bit_lengths[bit_length].N

    // number of MR tests to perform
    var repeat = bit_lengths[bit_length].repeat

    // make q
    var q, seed, tmp, u
    while (true) {
      seed = BigInt.randBigInt(bit_length)
      tmp = BigInt.mod(BigInt.add(seed, ONE), HLP.twotothe(bit_length))
      tmp = CryptoJS.SHA1(CryptoJS.enc.Latin1.parse(HLP.bigInt2bits(tmp)))
      u = CryptoJS.enc.Latin1.parse(HLP.bigInt2bits(seed))
      u = CryptoJS.SHA1(u)
      u = HLP.bigBitWise('XOR'
        , BigInt.str2bigInt(tmp.toString(CryptoJS.enc.Hex), 16)
        , BigInt.str2bigInt(u.toString(CryptoJS.enc.Hex), 16)
      )
      q = HLP.bigBitWise('OR', u, HLP.twotothe(N - 1))
      q = HLP.bigBitWise('OR', q, ONE)
      if (!MR(q, repeat)) continue
      primes[bit_length] = { q: q }
      t('q')
      break
    }

    // make p
    var p

    var n = Math.floor(bit_length / N)
    var b = (bit_length % N) - 1

    var counter = 0
      , offset = 2
      , W = ZERO

    var i, c, cspo, Lminus, X, V
    while (true) {

      // cache seed + offset
      cspo = BigInt.add(seed, BigInt.str2bigInt(offset.toString(), 10))

      for (i = 0; i < (n + 1); i++) {
        V = BigInt.add(cspo, BigInt.str2bigInt(i.toString(), 10))
        V = HLP.bigInt2bits(BigInt.mod(V, HLP.twotothe(N)))
        V = CryptoJS.SHA1(CryptoJS.enc.Latin1.parse(V))
        V = BigInt.str2bigInt(V.toString(CryptoJS.enc.Hex), 16)
        if (i === n) V = BigInt.mod(V, HLP.twotothe(b))
        V = BigInt.mult(V, HLP.twotothe(N * i))
        W = BigInt.add(W, V)
      }

      Lminus = HLP.twotothe(bit_length - 1)
      X = BigInt.add(W, Lminus)
      // console.log(HLP.between(X, Lminus, HLP.twotothe(bit_length)))

      c = BigInt.mod(X, BigInt.mult(TWO, q))
      p = BigInt.sub(X, BigInt.sub(c, ONE))

      if (!BigInt.greater(Lminus, p)) {
        // test the primality of p
        if (MR(p, repeat)) {
          primes[bit_length].p = p
          t('p')
          break
        }
      }

      offset += n + 1
      counter += 1

      if (counter >= (4 * bit_length)) return generatePrimes(bit_length)
    }

    // make g
    var p_minus = BigInt.sub(p, ONE)
    var e = BigInt.multMod(
        p_minus
      , BigInt.inverseMod(q, p)
      , p
    )
    var g, h = TWO
    while (true) {
      g = BigInt.powMod(h, e, p)
      if (!BigInt.greater(g, ONE)) {
        h = BigInt.add(h, ONE)
        continue
      }
      primes[bit_length].g = g
      t('g')
      return
    }

    throw new Error('Unreachable!')

  }

  function DSA(bit_length) {
    if (!(this instanceof DSA)) return new DSA(bit_length)

    // default to 1024
    bit_length = parseInt(bit_length ? bit_length : 1024, 10)

    if (!bit_lengths[bit_length])
      throw new Error('Unsupported bit length.')

    // set primes
    if (!primes[bit_length]) generatePrimes(bit_length)

    this.p = primes[bit_length].p
    this.q = primes[bit_length].q
    this.g = primes[bit_length].g

    // key type
    this.type = KEY_TYPE

    // private key
    this.x = makeRandom(ZERO, this.q)

    // public keys (p, q, g, y)
    this.y = BigInt.powMod(this.g, this.x, this.p)
  }

  DSA.prototype = {

    constructor: DSA,

    packPublic: function () {
      var str = this.type
      str += HLP.packMPI(this.p)
      str += HLP.packMPI(this.q)
      str += HLP.packMPI(this.g)
      str += HLP.packMPI(this.y)
      return str
    },

    sign: function (m) {
      m = CryptoJS.enc.Latin1.parse(m)  // CryptoJS.SHA1(m)
      m = BigInt.str2bigInt(m.toString(CryptoJS.enc.Hex), 16)
      var k, r = ZERO, s = ZERO
      while (BigInt.isZero(s) || BigInt.isZero(r)) {
        k = makeRandom(ZERO, this.q)
        r = BigInt.mod(BigInt.powMod(this.g, k, this.p), this.q)
        if (BigInt.isZero(r)) continue
        s = BigInt.inverseMod(k, this.q)
        s = BigInt.mult(s, BigInt.add(m, BigInt.mult(this.x, r)))
        s = BigInt.mod(s, this.q)
      }
      return [r, s]
    },

    fingerprint: function () {
      var pk = this.packPublic()
      if (this.type === KEY_TYPE) pk = pk.substring(2)
      pk = CryptoJS.enc.Latin1.parse(pk)
      return CryptoJS.SHA1(pk).toString(CryptoJS.enc.Hex)
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

  DSA.inherit = function (key) {
    key.__proto__ = DSA.prototype
    key.constructor = DSA
    key.type = KEY_TYPE
  }

}).call(this)