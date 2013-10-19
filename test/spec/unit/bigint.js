/*global describe it */
var assert = require('assert')
  , BigInt = require('../../../vendor/bigint.js')

describe('BigInt', function() {
  "use strict";

  it('should exponentiate a BigInt with base two', function () {
    assert.equal((Math.pow(2, 513)).toString(16), BigInt.bigInt2str(BigInt.twoToThe(513), 16))
  })

  it('should return a bit string of the proper length', function () {
    // 2^(8*3) < 2^(15*2) < 2^(8*4) === 4 bytes
    // chosen because each array element in bigint.js holds 15 bits
    // (on my machine) so it looks like [0, 0, 1]
    var test = BigInt.str2bigInt((Math.pow(2, 30)).toString(), 10)
    assert.equal(4, BigInt.bigInt2bits(test).length)
  })

  it('should handle shift distances greater than the bit length of x', function () {
    var bi = BigInt.str2bigInt("10000000000", 2)
    BigInt.rightShift_(bi, 12)
    assert.ok(BigInt.equalsInt(bi, 0))
    bi = BigInt.str2bigInt("10", 2)
    BigInt.rightShift_(bi, 26*3)
    assert.ok(BigInt.equalsInt(bi, 0))
  })

})