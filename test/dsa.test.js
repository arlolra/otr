var assert = require('assert')
  , hlp = require('../helpers.js')
  , dsa = require('../dsa.js')
  , BigInt = require('../vendor/bigint.js')

var key = new dsa.generateKey()

assert.ok(hlp.between(key.q, hlp.twotothe(159), hlp.twotothe(160)), 'In between.')

console.log('p: ' + BigInt.bigInt2str(key.p, 10))
console.log('q: ' + BigInt.bigInt2str(key.q, 10))
console.log('counter: ' + key.counter)