/*global describe beforeEach it */
var assert = require('assert')
  , keys = require('./data/keys.js')
  , CONST = require('../../../lib/const.js')
  , SM = require('../../../lib/sm.js')
  , OTR = require('../../../lib/otr.js')

describe('SM', function () {

  var userA, userB
  beforeEach(function () {
    var cb = function () {}
    var io = function (msg) { userA.receiveMsg(msg) }
    userB = new OTR(keys.userB, cb, io)
    userA = new OTR(keys.userA, cb, userB.receiveMsg)
  })

  it('should ensure message state is encrypted for SM', function () {
    userA.uicb = function (err, msg) {
      assert.equal(true, !!err, 'Plaintext should not SM.')
    }
    userA.sendQueryMsg()
    userA.msgstate = CONST.MSGSTATE_PLAINTEXT
    userA.smpSecret()
  })

  it('should require an secret to initiate SM', function () {
    userA.uicb = function (err, msg) {
      assert.equal(true, !!err, 'Secret required for SM.')
    }
    userA.sendQueryMsg()
    userA.smpSecret()
  })

  it.skip('should verify the SM secret', function () {
    userA.uicb = function (err, msg) {
      assert.equal(false, !!err, err)
      assert.equal(false, !!msg, msg)
    }

    userA.sendQueryMsg()  // must have AKEd for SM

    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')

    // figure out API for this
    userA.secret = 'applesAndOranges'
    userB.secret = 'applesAndOranges'

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

    userA.sm.initiate()

    assert.ok(userA.trust, 'Trust B? true')
    assert.ok(userB.trust, 'Trust A? true')
  })

})