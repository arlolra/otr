/*global describe before it */

var assert = require('assert')
  , OTR = require('../../../otr.js')
  , keys = require('./data/keys.js')
  , ParseOTR = require('../../../parse.js')

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
    var ui = function (msg) {
      assert.equal(userB.msgstate, 1, 'Encrypted')
      assert.equal(userA.msgstate, 1, 'Encrypted')
    }
    var io = function (msg) { userB.receiveMsg(msg) }
    userA = new OTR(keys.userA, ui, io)
    userB = new OTR(keys.userB, ui, userA.receiveMsg)

    assert.equal(userB.msgstate, 0, 'Plaintext')
    assert.equal(userA.msgstate, 0, 'Plaintext')

    userA.sendQueryMsg()
  })

})