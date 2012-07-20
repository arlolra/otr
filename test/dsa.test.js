var assert = require('assert')
  , hlp = require('../helpers.js')
  , dsa = require('../dsa.js')
  , BigInt = require('../vendor/bigint.js')

var key = new dsa.generateKey()

assert.ok(hlp.between(key.q, hlp.twotothe(159), hlp.twotothe(160)), 'In between.')