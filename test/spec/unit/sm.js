/*global describe beforeEach it */
var assert = require('assert')
  , keys = require('./data/keys.js')
  , CONST = require('../../../lib/const.js')
  , SM = require('../../../lib/sm.js')
  , OTR = require('../../../lib/otr.js')

describe('SM', function () {

  var userA, userB
  beforeEach(function () {
    userB = new OTR({ priv: keys.userB })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) { userB.receiveMsg(msg) })
  })

  it('should ensure message state is encrypted for SM', function (done) {
    userA.on('error', function (err) {
      assert.equal(true, !!err, err)
      done()
    })
    userA.smpSecret()
  })

  it('should require an secret to initiate SM', function (done) {
    userA.on('error', function (err) {
      assert.equal(true, !!err, err)
      done()
    })
    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        userA.smpSecret()
      }
    })
    userA.sendQueryMsg()
  })

  it.only('1 should verify the SM secret', function (done) {
    this.timeout(3500)
    var both = false

    userA.on('ui', function (msg) { assert.equal(false, !!msg, msg) })
    userA.on('error', function (err) { assert.equal(false, !!err, err) })

    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.ok(!userA.trust, 'Trust B? false')
        assert.ok(!userB.trust, 'Trust A? false')
        userA.smpSecret('applesAndOranges')
      }
    })

    userA.on('smp', function (type, data) {
      if (type === 'trust') {
        assert.ok(userA.trust, 'Trust B? false')
        if (both) done()
        else both = true
      }
    })

    userB.sendQueryMsg()  // must have AKEd for SM

    // callback to ask smp question
    // should be passed in as opts.smcb
    userB.on('smp', function (type, data) {
      switch (type) {
        case 'question':
          userB.smpSecret('applesAndOranges')
          break
        case 'trust':
          assert.ok(userB.trust, 'Trust A? false')
          if (both) done()
          else both = true
          break
        default:
          throw new Error('should not be here')
      }
    })

  })


  it('2 should verify the SM secret failed', function () {
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
          this.smpSecret('bananasAndPears')
          break
        case 'trust':
          assert.ok(!this.trust)
          break
        default:
          throw new Error('should not be here')
      }
    }

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

    userA.smpSecret('applesAndOranges')

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

  })

  it('3 should verify the SM secret with question', function () {
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
        default:
          throw new Error('should not be here')
      }
    }

    assert.ok(!userA.trust, 'Trust B? false')
    assert.ok(!userB.trust, 'Trust A? false')

    userA.smpSecret('applesAndOranges', 'What is difference?')

    assert.ok(userA.trust, 'Trust B? false')
    assert.ok(userB.trust, 'Trust A? false')

  })

})