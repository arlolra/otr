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
    var opts = {}
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

  it('should verify the SM secret', function () {
    userA.uicb = function (err, msg) {
      assert.equal(false, !!err, err)
      assert.equal(false, !!msg, msg)
    }

    userA.sendQueryMsg()  // must have AKEd for SM

    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')

    // callback to ask smp question
    // should be passed in as opts.smcb
    userB._smcb = function (type, data) {
      switch (type) {
        case 'question':
          this.smpSecret('applesAndOranges')
          break
        case 'trust':
          assert.ok(this.trust)
          break
        case 'abort':
          assert.ok(!this.trust)
          break
        default:
          throw 'should not be here'
      }
    }

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

    userA.smpSecret('applesAndOranges')

    assert.ok(userA.trust, 'Trust B? false')
    assert.ok(userB.trust, 'Trust A? false')

  })

  it('should verify the SM secret with question', function () {
    userA.uicb = function (err, msg) {
      assert.equal(false, !!err, err)
      assert.equal(false, !!msg, msg)
    }

    userA.sendQueryMsg()  // must have AKEd for SM

    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')

    // callback to ask smp question
    // should be passed in as opts.smcb
    userB._smcb = function (type, data) {
      switch (type) {
        case 'question':
          assert.equal('What is difference?', data, type)
          this.smpSecret('applesAndOranges')
          break
        case 'trust':
          assert.ok(this.trust)
          break
        case 'abort':
          assert.ok(!this.trust)
          break
        default:
          throw 'should not be here'
      }
    }

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

    userA.smpSecret('applesAndOranges', 'What is difference?')

    assert.ok(userA.trust, 'Trust B? false')
    assert.ok(userB.trust, 'Trust A? false')

  })

})