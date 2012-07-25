var assert = require('assert')
  , OTR = require('../otr.js')

var bob = new OTR()
var alice = new OTR()

bob.initiateAKE(alice.receiveMsg)