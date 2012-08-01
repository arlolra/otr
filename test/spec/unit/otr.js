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

})