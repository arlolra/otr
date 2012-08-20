/*global describe before it */
var assert = require('assert')
  , OTR = require('../../../lib/otr.js')
  , HLP = require('../../../lib/helpers.js')
  , keys = require('./data/keys.js')
  , ParseOTR = require('../../../lib/parse.js')
  , STATES = require('../../../lib/states.js')

describe('OTR', function () {

  var cb = function () {}

  it('should initiate a new OTR object', function () {
    var userA = new OTR(keys.userA, cb, cb)
  })

  it('should initiate AKE', function () {
    var userB = new OTR(keys.userB, cb, cb)
    var userA = new OTR(keys.userA, cb, function (msg) {
      msg = ParseOTR.parseMsg(userB, msg)
      assert.equal('\x02', msg.type, 'Message type.')
      assert.equal('\x00\x02', msg.version, 'Message version.')
    })
    // query otr
    userA.receiveMsg('?OTR?v2?')
  })

  it('should query with versions one and two', function () {
    var userB = new OTR(keys.userB, cb, cb)
    var userA = new OTR(keys.userA, cb, function (msg) {
      assert.equal('?OTR?v2?', msg, 'Versions 1 and 2.')
      userB.receiveMsg(msg)
      assert.ok(userB.versions['1'], 'version 1 & 2')
      assert.ok(userB.versions['2'], 'version 1 & 2')
    })
    userA.ALLOW_V1 = true
    userA.sendQueryMsg()
  })

  it('should go through the ake dance', function () {
    var userA, userB
    var ui = function (msg) { console.log(msg) }
    var checkstate = function (user) {
      switch (user.authstate) {
        case STATES.AUTHSTATE_AWAITING_DHKEY:
          // This fails sometimes because bigInt2bits trims leading zeros
          // and r is random bits. So, there's a slightly greater than
          // 1/256 chance that bytes are missing.
          // assert.equal(HLP.bigInt2bits(userB.ake.r).length, 128 / 8)
          assert.equal(userB.ake.myhashed.length, (256 / 8) + 4)
          break
        case STATES.AUTHSTATE_AWAITING_REVEALSIG:
          assert.equal(user.ake.encrypted.length, 192 + 4)
          assert.equal(user.ake.hashed.length, 256 / 8)
          break
        case STATES.AUTHSTATE_AWAITING_SIG:
          assert.equal(user.ake.their_y.length, 192)
          assert.equal(user.ake.ssid.length, 64 / 8)
          assert.equal(user.ake.c.length, 128 / 8)
          assert.equal(user.ake.c_prime.length, 128 / 8)
          assert.equal(user.ake.m1.length, 256 / 8)
          assert.equal(user.ake.m2.length, 256 / 8)
          assert.equal(user.ake.m1_prime.length, 256 / 8)
          assert.equal(user.ake.m2_prime.length, 256 / 8)
          break
      }
    }
    userA = new OTR(keys.userA, ui, function (msg) {
      checkstate(userA)
      userB.receiveMsg(msg)
    })
    userB = new OTR(keys.userB, ui, function (msg) {
      checkstate(userB)
      userA.receiveMsg(msg)
    })

    assert.equal(userB.msgstate, STATES.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, STATES.MSGSTATE_PLAINTEXT, 'Plaintext')

    userA.sendQueryMsg()  // ask to initiate ake

    assert.equal(userB.msgstate, STATES.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, STATES.MSGSTATE_ENCRYPTED, 'Encrypted')
  })

  it('should receive an encrypted message', function () {
    var msgs = ['Hope this works.', 'Second message.', 'Third!', '4', '5', '6', '7', '8888888888888888888']
    var counter = 0

    var userA, userB
    var ui = function (msg) {
      assert.equal(msgs[counter++], msg, 'Encrypted message.')
    }
    var io = function (msg) { userB.receiveMsg(msg) }
    userA = new OTR(keys.userA, ui, io)
    userB = new OTR(keys.userB, ui, userA.receiveMsg)
    userA.sendQueryMsg()
    userB.sendMsg(msgs[counter])
    userB.sendMsg(msgs[counter])
    userA.sendMsg(msgs[counter])
    userA.sendMsg(msgs[counter])
    userA.sendMsg(msgs[counter])
    userB.sendMsg(msgs[counter])
    userB.sendMsg(msgs[counter])
    userA.sendMsg(msgs[counter])
  })

  it('should send fragments', function(done){
    this.timeout(10000)
    var msgs = ['Hope this works.', 'Second message.', 'This is a bit of a longer message.', 'Some messages can be quite long and must be fragmented over several pieces.']
    var counter = 0

    var userA, userB
    var ui = function (msg) {
      assert.equal(msgs[counter++], msg, 'Encrypted message.')
      if(counter == 4) done()
    }
    var io = function (msg) { userB.receiveMsg(msg) }
    userA = new OTR(keys.userA, ui, io, { fragment_size: 20 })
    userB = new OTR(keys.userB, ui, userA.receiveMsg)
    userA.sendQueryMsg()
    userB.on('encrypted', function(){
      userB.sendMsg(msgs[counter])
      userB.sendMsg(msgs[counter])
      userA.sendMsg(msgs[counter], function(){
        userA.sendMsg(msgs[counter])
      })
    })
  })

})
