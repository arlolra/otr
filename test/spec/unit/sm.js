/*global describe beforeEach it */
var assert = require('assert')
  , keys = require('./data/keys.js')
  , CONST = require('../../../lib/const.js')
  , SM = require('../../../lib/sm.js')
  , OTR = require('../../../lib/otr.js')

describe('SM', function () {

  var userA, userB
  beforeEach(function () {
    var cb = function (err) { if (err) throw err }
    var io = function (msg) { userA.receiveMsg(msg) }
    var opts = { debug: true }
    userB = new OTR(keys.userB, cb, io, opts)
    userA = new OTR(keys.userA, cb, userB.receiveMsg, opts)
  })

  it('should ensure message state is encrypted for SM', function () {
    userA.uicb = function (err, msg) {
      assert.equal(true, !!err, err)
    }
    userA.smpSecret()
  })

  it('should require an secret to initiate SM', function () {
    userA.uicb = function (err, msg) {
      assert.equal(true, !!err, err)
    }
    userA.sendQueryMsg()
    userA.smpSecret()
  })

  it.skip('should verify the SM secret', function (done) {
    userA.uicb = function (err, msg) {
      assert.equal(false, !!err, err)
      assert.equal(false, !!msg, msg)
    }

    userA.sendQueryMsg()  // must have AKEd for SM

    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')

    // callback to ask smp question
    userB.smcb = function (question) {
      console.log("question")
      userB.smpSecret('applesAndOranges')
    }

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

    userA.smpSecret('applesAndOranges')

  })

})