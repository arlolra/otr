var assert = require('assert')
  , HLP = require('../helpers.js')
  , DSA = require('../dsa.js')
  , BigInt = require('../vendor/bigint.js')

describe('DSA', function(){
  var key;
  before(function(){
    key = new dsa.Key()
    console.log('p: ' + BigInt.bigInt2str(key.p, 10))
    console.log('q: ' + BigInt.bigInt2str(key.q, 10))
    console.log('x: ' + BigInt.bigInt2str(key.x, 10))
    console.log('g: ' + BigInt.bigInt2str(key.g, 10))
    console.log('counter: ' + key.counter)
  });

  it('should generate a key with q > 2^159 and q < 2^160', function(){
    assert.ok(
            hlp.between(key.q, hlp.twotothe(159), hlp.twotothe(160)),'In between.')
  });

  it('should generate a key with q being a multiple of q', function(){
    var quotient = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
      , remainder = BigInt.str2bigInt('0', 10, BigInt.bitSize(key.p))
    var p_minus = BigInt.sub(key.p, BigInt.str2bigInt('1', 10))
    BigInt.divide_(p_minus, key.q, quotient, remainder)
    assert.ok(BigInt.isZero(remainder), 'Multiple.')
  });

 
  it('should verify a valid signature', function(){
    var s = key.sign('abc')
    assert.equal(1, dsa.verify(key, 'abc', s[0], s[1]), 'Verify signed message.')
  });

  it('should parse a given public key into the correct parameters', function(){
      var par = dsa.parsePublic(key.packPublic())
      assert.ok(BigInt.equals(key.p, par.p), 'Pees are good.')
      assert.ok(BigInt.equals(key.q, par.q), 'Qs.')
      assert.ok(BigInt.equals(key.g, par.g), 'Gs.')
      assert.ok(BigInt.equals(key.y, par.y), 'Ys.')
  });
});
