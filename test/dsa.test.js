var assert = require('assert')
  , hlp = require('../helpers.js')
  , dsa = require('../dsa.js')
  , BigInt = require('../vendor/bigint.js')

var key = new dsa.Key()

assert.ok(
	hlp.between(key.q, hlp.twotothe(159), hlp.twotothe(160)),'In between.')

var quotient = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
  , remainder = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
var p_minus = BigInt.sub(key.p, BigInt.str2bigInt('1', 10))
BigInt.divide_(p_minus, key.q, quotient, remainder)
assert.ok(BigInt.isZero(remainder), 'Multiple.')

console.log('p: ' + BigInt.bigInt2str(key.p, 10))
console.log('q: ' + BigInt.bigInt2str(key.q, 10))
console.log('x: ' + BigInt.bigInt2str(key.x, 10))
console.log('g: ' + BigInt.bigInt2str(key.g, 10))
console.log('counter: ' + key.counter)

var s = key.sign('abc')
assert.equal(1, key.verify('abc', s[0], s[1]), 'Verify signed message.')