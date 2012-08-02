/*global describe before it */

var assert = require('assert')
  , OTR = require('../../../otr.js')
  , keys = require('./data/keys.js')
  , ParseOTR = require('../../../parse.js')

describe('OTR', function () {

  it('should initiate a new OTR object', function () {
    var userA = new OTR(keys.userA)
  })

  it('should initiate AKE', function () {
    var userA = new OTR(keys.userA)
    var userB = new OTR(keys.userB)

    // query otr
    userA.receiveMsg('?OTR?v2?', null, function (msg) {
      msg = ParseOTR.parseMsg(userB, msg)
      assert.equal('\x02', msg.type, 'Message type.')
      assert.equal('\x00\x02', msg.version, 'Message version.')
    })
  })

  it('should query with versions one and two', function () {
    var userA = new OTR(keys.userA)
    var userB = new OTR(keys.userB)
    userA.ALLOW_V1 = true
    userA.sendQueryMsg(function (msg) {
      assert.equal('?OTR?v2?', msg, 'Versions 1 and 2.')
      userB.receiveMsg(msg, null, function (msg) {
        assert.ok(userB.versions['1'], 'version 1 & 2')
        assert.ok(userB.versions['2'], 'version 1 & 2')
      })
    })
  })

})