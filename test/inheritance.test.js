var assert = require('assert')
  , OTR = require('../otr.js')

var otr = OTR()

assert.ok(otr instanceof OTR, 'Not an instance.')
assert.ok(otr.constructor === OTR, 'Constructor not equal.')