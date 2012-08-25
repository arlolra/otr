/*global describe before it */
var assert = require('assert')
  , HLP = require('../../../lib/helpers.js')
  , DSA = require('../../../lib/dsa.js')
  , BigInt = require('../../../vendor/bigint.js')

describe('DSA', function() {

  var key

  it('should generate a key - timed', function () {
    key = new DSA()   
  })

  it('should generate a key with q > 2^159 and q < 2^160', function () {
    assert.ok(HLP.between(key.q, HLP.twotothe(159), HLP.twotothe(160)),'In between.')
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
    var finger = DSA.fingerprint(key)
    assert.equal(40, finger.length, 'SHA1 Hex')
  })

})