var assert = require('assert')
  , HLP = require('../helpers.js')
  , DSA = require('../dsa.js')
  , BigInt = require('../vendor/bigint.js')

var key = new DSA.Key()

describe('DSA', function(){
  var key;
  before(function(){
    key = new DSA.Key()
    console.log('p: ' + BigInt.bigInt2str(key.p, 10))
    console.log('q: ' + BigInt.bigInt2str(key.q, 10))
    console.log('x: ' + BigInt.bigInt2str(key.x, 10))
    console.log('g: ' + BigInt.bigInt2str(key.g, 10))
    console.log('counter: ' + key.counter)
  });

assert.ok(
	HLP.between(key.q, HLP.twotothe(159), HLP.twotothe(160)),'In between.')

var quotient = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
  , remainder = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
var p_minus = BigInt.sub(key.p, BigInt.str2bigInt('1', 10))
BigInt.divide_(p_minus, key.q, quotient, remainder)
assert.ok(BigInt.isZero(remainder), 'Multiple.')

var s = key.sign('abc')
assert.equal(1, DSA.verify(key, 'abc', s[0], s[1]), 'Verify signed message.')

var par = DSA.parsePublic(key.packPublic())
assert.ok(BigInt.equals(key.p, par.p), 'Pees are good.')
assert.ok(BigInt.equals(key.q, par.q), 'Qs.')
assert.ok(BigInt.equals(key.g, par.g), 'Gs.')
assert.ok(BigInt.equals(key.y, par.y), 'Ys.')
