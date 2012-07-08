var assert = require('assert')
  , SM = require('../sm.js')

var alice = new SM('arlo')
var bob = new SM('arlo')

alice.sendMsg(null, bob)