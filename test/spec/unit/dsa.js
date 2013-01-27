/*global describe before it */
var assert = require('assert')
  , HLP = require('../../../lib/helpers.js')
  , DSA = require('../../../lib/dsa.js')
  , BigInt = require('../../../vendor/bigint.js')

describe('DSA', function() {

  var key, L, N
  before(function () {
    // time the keygen but require before
    process.stdout.write('      generating the key ... ')
    var start = (new Date()).getTime()
    L = 1024
    N = 160
    key = new DSA(null, { bit_length: L })
    console.log('(' + ((new Date()).getTime() - start) + 'ms)')
  })

  it('should generate a key with q > 2^(N - 1) and q < 2^N', function () {
    assert.ok(HLP.between(key.q, HLP.twotothe(N - 1), HLP.twotothe(N)), 'q in between.')
  })

  it('should generate a key with p > 2^(L - 1) and p < 2^L', function () {
    assert.ok(HLP.between(key.p, HLP.twotothe(L - 1), HLP.twotothe(L)), 'p in between.')
  })

  it('should generate a key with q being a multiple of q', function () {
    var quotient = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
      , remainder = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
    var p_minus = BigInt.sub(key.p, BigInt.str2bigInt('1', 10))
    BigInt.divide_(p_minus, key.q, quotient, remainder)
    assert.ok(BigInt.isZero(remainder), 'Multiple.')
  })

  it('should verify a valid signature', function () {
    var s = key.sign('abc')
    assert.equal(1, DSA.verify(key, 'abc', s[0], s[1]), 'Verify signed message.')
  })

  it('should parse a given public key into the correct parameters', function () {
    var par = DSA.parsePublic(key.packPublic())
    assert.ok(BigInt.equals(key.p, par.p), 'Pees are good.')
    assert.ok(BigInt.equals(key.q, par.q), 'Qs.')
    assert.ok(BigInt.equals(key.g, par.g), 'Gs.')
    assert.ok(BigInt.equals(key.y, par.y), 'Ys.')
  })

  it('should return a fingerprint for the public key', function () {
    var finger = key.fingerprint()
    assert.equal(40, finger.length, 'SHA1 Hex')
  })

  it('should parse a given private key into the correct params', function () {
    var par = DSA.parsePrivate(key.packPrivate())
    assert.ok(BigInt.equals(key.p, par.p), 'Pees are good.')
    assert.ok(BigInt.equals(key.q, par.q), 'Qs.')
    assert.ok(BigInt.equals(key.g, par.g), 'Gs.')
    assert.ok(BigInt.equals(key.y, par.y), 'Ys.')
    assert.ok(BigInt.equals(key.x, par.x), 'Xs.')
  })

})