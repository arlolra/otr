// DSA
// http://www.itl.nist.gov/fipspubs/fip186.htm

;(function () {
  "use strict";

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

  // http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn2.js

  var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
  var lplim = (1 << 26) / lowprimes[lowprimes.length - 1]

  function isProbablePrime(x, repeat) {
    var t = x.length - 1
    for (; t >= 0 && x[t] === 0; t--) ;

    var i
    if(t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
      for (i = 0; i < lowprimes.length; ++i)
        if (x[0] == lowprimes[i]) return true
      return false
    }

    // even
    if ((x[0] % 2) === 0) return false

    i = 1
    var m, j
    while (i < lowprimes.length) {
      m = lowprimes[i]
      j = i + 1
      while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
      m = BigInt.modInt(x, m)
      while (i < j) if (m % lowprimes[i++] === 0) return false
    }

    return millerRabin(x, repeat)
  }

  function lbit(x) {
    if (x === 0) return -1
    var k = 0
    while ((x & 1) === 0) x >>= 1, k++
    return k
  }

  function lowestSetBit(x) {
    var t = x.length - 1
    for (; t >= 0 && x[t] === 0; t--) ;
    var i = 0
    for (; i < t; i++)
      if (x[i] !== 0) return (i * BigInt.bpe) + lbit(x[i])
    return -1
  }

  function millerRabin(x, repeat) {
    var n1 = BigInt.sub(x, ONE)

    var k = lowestSetBit(n1)
    if (k <= 0) return false

    var r = BigInt.dup(n1)
    BigInt.rightShift_(r, k)

    repeat = (repeat + 1) >> 1
    if (repeat > lowprimes.length) repeat = lowprimes.length;

    var a, i, y, j, bases = []
    for (i = 0; i < repeat; i++) {

      // Pick bases at random, instead of starting at 2
      while (!a || ~bases.indexOf(a))
        a = lowprimes[Math.floor(Math.random() * lowprimes.length)]

      bases.push(a)
      y = BigInt.powMod(BigInt.int2bigInt(a, 0), r, x)

      if (!BigInt.equals(y, ONE) && !BigInt.equals(y, n1)) {
        j = 1
        while (j++ < k && !BigInt.equals(y, n1)) {
          y = BigInt.powMod(y, TWO, x)
          if (BigInt.equals(y, ONE)) return false
        }
        if (!BigInt.equals(y, n1)) return false
      }

    }

    return true
  }

  var bit_lengths = {
      '1024': { N: 160, repeat: 40 }  // 40x should give 2^-80 confidence
    , '2048': { N: 224, repeat: 56 }
    , '3072': { N: 256, repeat: 64 }
  }

  var primes = {}

  function shaBigInt(bi) {
    bi = CryptoJS.enc.Latin1.parse(HLP.bigInt2bits(bi))
    bi = CryptoJS.SHA1(bi)
    return HLP.bits2bigInt(bi.toString(CryptoJS.enc.Latin1))
  }

  function inc_(bi, TN) {
    BigInt.addInt_(bi, 1)
    BigInt.mod_(bi, TN)
  }

  function generatePrimesFIPS(bit_length) {

    var t = timer()  // for debugging

    // number of MR tests to perform
    var repeat = bit_lengths[bit_length].repeat

    var N = bit_lengths[bit_length].N
    var TN = HLP.twotothe(N)

    var n = Math.floor((bit_length - 1) / N)
    var b = (bit_length - 1) % N

    var bl4 = 4 * bit_length
    var brk = false

    var q, p, seed, u, tmp, counter, offset, k, cspo, V, W, X, LM1, c
    for (;;) {

      seed = BigInt.randBigInt(N)

      tmp = BigInt.dup(seed)
      inc_(tmp, TN)
      tmp = shaBigInt(tmp)

      u = shaBigInt(seed)
      u = HLP.bigBitWise('XOR', u, tmp)

      q = HLP.bigBitWise('OR', u, HLP.twotothe(N - 1))
      q[0] |= 1

      if (!isProbablePrime(q, repeat)) continue

      t('q')
      offset = BigInt.dup(seed)
      inc_(offset, TN)

      for (counter = 0; counter < bl4; counter++) {
        W = ZERO
        cspo = BigInt.addInt(seed, offset)

        for (k = 0; k < (n + 1); k ++) {
          inc_(offset, TN)
          V = shaBigInt(offset)
          if (k === n) V = BigInt.mod(V, HLP.twotothe(b))
          V = BigInt.mult(V, HLP.twotothe(N * k))
          W = BigInt.add(W, V)
        }

        LM1 = HLP.twotothe(bit_length - 1)
        X = BigInt.add(W, LM1)

        c = BigInt.mod(X, BigInt.mult(q, TWO))
        p = BigInt.sub(X, BigInt.sub(c, ONE))

        if (BigInt.greater(LM1, p)) continue
        if (!isProbablePrime(p, repeat)) continue

        t('p')
        primes[bit_length] = { p: p, q: q }
        brk = true
        break
      }

      if (brk) break
    }

    var h = BigInt.dup(TWO)
    var pm1 = BigInt.sub(p, ONE)
    var e = BigInt.multMod(pm1, BigInt.inverseMod(q, p), p)

    var g
    for (;;) {
      g = BigInt.powMod(h, e, p)
      if (BigInt.equals(g, ONE)) {
        h = BigInt.add(h, ONE)
        continue
      }
      primes[bit_length].g = g
      t('g')
      return
    }

    throw new Error('Unreachable!')
  }

  function generatePrimesGO(bit_length) {

    var t = timer()  // for debugging

    // number of MR tests to perform
    var repeat = bit_lengths[bit_length].repeat

    var N = bit_lengths[bit_length].N

    var LM1 = HLP.twotothe(bit_length - 1)
    var bl4 = 4 * bit_length
    var brk = false

    // go lang http://golang.org/src/pkg/crypto/dsa/dsa.go

    var q, p, rem, counter
    for (;;) {

      q = BigInt.randBigInt(N, 1)
      q[0] |= 1

      if (!isProbablePrime(q, repeat)) continue
      t('q')

      for (counter = 0; counter < bl4; counter++) {
        p = BigInt.randBigInt(bit_length, 1)
        p[0] |= 1

        rem = BigInt.mod(p, q)
        rem = BigInt.sub(rem, ONE)
        p = BigInt.sub(p, rem)

        if (BigInt.greater(LM1, p)) continue
        if (!isProbablePrime(p, repeat)) continue

        t('p')
        primes[bit_length] = { p: p, q: q }
        brk = true
        break
      }

      if (brk) break
    }

    var h = BigInt.dup(TWO)
    var pm1 = BigInt.sub(p, ONE)
    var e = BigInt.multMod(pm1, BigInt.inverseMod(q, p), p)

    var g
    for (;;) {
      g = BigInt.powMod(h, e, p)
      if (BigInt.equals(g, ONE)) {
        h = BigInt.add(h, ONE)
        continue
      }
      primes[bit_length].g = g
      t('g')
      return
    }

    throw new Error('Unreachable!')
  }

  function DSA(obj, opts) {
    if (!(this instanceof DSA)) return new DSA(obj, opts)

    // options
    opts = opts || {}

    // inherit
    if (obj) {
      var self = this
      ;['p', 'q', 'g', 'y', 'x'].forEach(function (prop) {
        self[prop] = obj[prop]
      })
      this.type = obj.type || KEY_TYPE
      return
    }

    // default to 1024
    var bit_length = parseInt(opts.bit_length ? opts.bit_length : 1024, 10)

    if (!bit_lengths[bit_length])
      throw new Error('Unsupported bit length.')

    // set primes
    if (!primes[bit_length]) {
      if (opts.fips) generatePrimesFIPS(bit_length)
      else generatePrimesGO(bit_length)
    }

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

    packPrivate: function () {
      var str = this.packPublic() + HLP.packMPI(this.x)
      str = CryptoJS.enc.Latin1.parse(str)
      return str.toString(CryptoJS.enc.Base64)
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

  DSA.parsePublic = function (str, priv) {
    var fields = ['SHORT', 'MPI', 'MPI', 'MPI', 'MPI']
    if (priv) fields.push('MPI')
    str = HLP.splitype(fields, str)
    var obj = {
        type: str[0]
      , p: HLP.readMPI(str[1])
      , q: HLP.readMPI(str[2])
      , g: HLP.readMPI(str[3])
      , y: HLP.readMPI(str[4])
    }
    if (priv) obj.x = HLP.readMPI(str[5])
    return new DSA(obj)
  }

  function tokenizeStr(str) {
    var start, end

    start = str.indexOf("(")
    end = str.lastIndexOf(")")

    if (start < 0 || end < 0)
      throw new Error("Malformed S-Expression")

    str = str.substring(start + 1, end)

    var splt = str.search(/\s/)
    var obj = {
        type: str.substring(0, splt)
      , val: []
    }

    str = str.substring(splt + 1, end)
    start = str.indexOf("(")

    if (start < 0) obj.val.push(str)
    else {

      var i, len, ss, es
      while (start > -1) {
        i = start + 1
        len = str.length
        for (ss = 1, es = 0; i < len && es < ss; i++) {
          if (str[i] === "(") ss++
          if (str[i] === ")") es++
        }
        obj.val.push(tokenizeStr(str.substring(start, ++i)))
        str = str.substring(++i)
        start = str.indexOf("(")
      }

    }
    return obj
  }

  function parseLibotr(obj) {
    if (!obj.type) throw new Error("Parse error.")

    var o, val
    if (obj.type === "privkeys") {
      o = []
      obj.val.forEach(function (i) {
        o.push(parseLibotr(i))
      })
      return o
    }

    o = {}
    obj.val.forEach(function (i) {

      val = i.val[0]
      if (typeof val === "string") {

        if (val.indexOf("#") === 0) {
          val = val.substring(1, val.lastIndexOf("#"))
          val = BigInt.str2bigInt(val, 16)
        }

      } else {
        val = parseLibotr(i)
      }

      o[i.type] = val
    })

    return o
  }

  DSA.parsePrivate = function (str, libotr) {
    if (!libotr) {
      str = CryptoJS.enc.Base64.parse(str)
      str = str.toString(CryptoJS.enc.Latin1)
      return DSA.parsePublic(str, true)
    }
    // only returning the first key found
    return parseLibotr(tokenizeStr(str))[0]["private-key"].dsa
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

}).call(this)