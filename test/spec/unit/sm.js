/*global describe beforeEach it */

var assert = require('assert')
  , OTR = require('../../../otr.js')
  , keys = require('./data/keys.js')
  , SM = require('../../../sm.js')

describe('SM', function () {

  var userA, userB
  beforeEach(function () {
    var cb = function () {}
    var io = function (msg) { userA.receiveMsg(msg) }
    userB = new OTR(keys.userB, cb, io)
    userA = new OTR(keys.userA, cb, userB.receiveMsg)
  })

  it('should ensure message state is encrypted for SM', function () {
    userA.uicb = function (msg) {
      assert.equal(true, !!msg, 'Plaintext should not SM.')
    }
    userA.sendQueryMsg()
    userA.msgstate = 0
    userA.sm.initiate()
  })

  it('should verify the SM secret', function () {
    userA.uicb = function (msg) {
      assert.equal(false, !!msg, msg)
    }

    userA.sendQueryMsg()  // must have AKEd for SM

    assert.equal(userB.msgstate, 1, 'Encrypted')
    assert.equal(userA.msgstate, 1, 'Encrypted')

    // figure out API for this
    userA.secret = 'applesAndOranges'
    userB.secret = 'applesAndOranges'

    userA.sm.initiate()
  })

})