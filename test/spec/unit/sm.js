/*global describe beforeEach it */
var assert = require('assert')
  , keys = require('./data/keys.js')
  , CONST = require('../../../lib/const.js')
  , OTR = require('../../../lib/otr.js')

describe('SM', function () {
  "use strict";

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
      assert.ok(err, err)
      done()
    })
    userA.smpSecret()
  })

  it('should require an secret to initiate SM', function (done) {
    userA.on('error', function (err) {
      assert.ok(err, err)
      done()
    })
    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        userA.smpSecret()
      }
    })
    userA.sendQueryMsg()
  })

  it('1 should verify the SM secret', function (done) {
    this.timeout(15000)
    var both = false

    userA.on('ui', function (msg) { assert.ifError(msg, msg) })
    userA.on('error', function (err) { assert.ifError(err, err) })

    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.ifError(userA.trust, 'Trust B? false')
        assert.ifError(userB.trust, 'Trust A? false')
        userA.smpSecret('applesAndOranges')
      }
    })

    userA.on('smp', function (type, one, two) {
      if (type === 'trust') {
        assert.ok(one, 'Trust B? false')
        assert.equal(two, 'asked', 'Trust B? false')
        assert.ok(userA.trust, 'Trust B? false')
        if (both) done()
        else both = true
      } else {
        assert.ifError(true)
      }
    })

    userB.sendQueryMsg()  // must have AKEd for SM

    userB.on('smp', function (type, one, two) {
      switch (type) {
        case 'question':
          userB.smpSecret('applesAndOranges')
          break
        case 'trust':
          assert.ok(one, 'Trust A? false')
          assert.equal(two, 'answered', 'Trust A? false')
          assert.ifError(userB.trust, 'Trust A? false')
          if (both) done()
          else both = true
          break
        default:
          assert.ifError(true)
      }
    })

  })

  it('2 should verify the SM secret failed', function (done) {
    this.timeout(15000)
    var both = false

    userA.on('ui', function (msg) { assert.ifError(msg, msg) })
    userA.on('error', function (err) { assert.ifError(err, err) })

    userA.on('smp', function (type, one, two) {
      if (type === 'trust') {
        assert.equal(two, 'asked')
        assert.ifError(one)
        assert.ifError(userA.trust)
        if (both) done()
        else both = true
      } else {
        assert.ifError(true)
      }
    })

    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.ifError(userA.trust, 'Trust B? false')
        assert.ifError(userB.trust, 'Trust A? false')
        userA.smpSecret('applesAndOranges')
      }
    })

    userB.sendQueryMsg()  // must have AKEd for SM

    userB.on('smp', function (type, one, two) {
      switch (type) {
        case 'question':
          userB.smpSecret('bananasAndPears')
          break
        case 'trust':
          assert.ifError(one, 'Trust A? false')
          assert.equal(two, 'answered', 'Trust A? false')
          assert.ifError(userB.trust)
          if (both) done()
          else both = true
          break
        default:
          assert.ifError(true)
      }
    })
  })

  it('3 should verify the SM secret with question', function (done) {
    this.timeout(15000)
    var both = false

    userA.on('ui', function (msg) { assert.ifError(msg, msg) })
    userA.on('error', function (err) { assert.ifError(err, err) })

    userA.on('smp', function (type, one, two) {
      if (type === 'trust') {
        assert.ok(one)
        assert.equal(two, 'asked')
        assert.ok(userA.trust)
        if (both) done()
        else both = true
      } else {
        assert.ifError(true)
      }
    })

    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.ifError(userA.trust, 'Trust B? false')
        assert.ifError(userB.trust, 'Trust A? false')
        userA.smpSecret('applesAndOranges', 'What is difference?')
      }
    })

    userB.sendQueryMsg()  // must have AKEd for SM

    userB.on('smp', function (type, one, two) {
      switch (type) {
        case 'question':
          assert.equal('What is difference?', one, type)
          userB.smpSecret('applesAndOranges')
          break
        case 'trust':
          assert.ok(one)
          assert.equal(two, 'answered')
          assert.ifError(userB.trust)
          if (both) done()
          else both = true
          break
        default:
          assert.ifError(true)
      }
    })
  })

  it('4 should verify the SM secret in a webworker', function (done) {
    this.timeout(15000)
    var both = false

    // use webworkers; default options
    userA.smw = {}
    userB.smw = {}

    userA.on('ui', function (msg) { assert.ifError(msg, msg) })
    userA.on('error', function (err) { assert.ifError(err, err) })

    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.ifError(userA.trust, 'Trust B? false')
        assert.ifError(userB.trust, 'Trust A? false')
        userA.smpSecret('applesAndOranges')
      }
    })

    userA.on('smp', function (type, one, two) {
      if (type === 'trust') {
        assert.ok(one)
        assert.equal(two, 'asked')
        assert.ok(userA.trust, 'Trust B? false')
        if (both) done()
        else both = true
      } else {
        assert.ifError(true)
      }
    })

    userB.sendQueryMsg()  // must have AKEd for SM

    userB.on('smp', function (type, one, two) {
      switch (type) {
        case 'question':
          userB.smpSecret('applesAndOranges')
          break
        case 'trust':
          assert.ok(one)
          assert.equal(two, 'answered')
          assert.ifError(userB.trust, 'Trust A? false')
          if (both) done()
          else both = true
          break
        default:
          assert.ifError(true)
      }
    })

  })

  it('5 should verify the SM secret failed in a webworker', function (done) {
    this.timeout(15000)
    var both = false

    // use webworkers; default options
    userA.smw = {}
    userB.smw = {}

    userA.on('ui', function (msg) { assert.ifError(msg, msg) })
    userA.on('error', function (err) { assert.ifError(err, err) })

    userA.on('smp', function (type, one, two) {
      if (type === 'trust') {
        assert.equal(two, 'asked')
        assert.ifError(one)
        assert.ifError(userA.trust)
        if (both) done()
        else both = true
      } else {
        assert.ifError(true)
      }
    })

    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.ifError(userA.trust, 'Trust B? false')
        assert.ifError(userB.trust, 'Trust A? false')
        userA.smpSecret('applesAndOranges')
      }
    })

    userB.sendQueryMsg()  // must have AKEd for SM

    userB.on('smp', function (type, one, two) {
      switch (type) {
        case 'question':
          userB.smpSecret('bananasAndPears')
          break
        case 'trust':
          assert.equal(two, 'answered')
          assert.ifError(one)
          assert.ifError(userB.trust)
          if (both) done()
          else both = true
          break
        default:
          assert.ifError(true)
      }
    })
  })

})