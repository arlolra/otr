var assert = require('assert')
  , SM = require('../../../sm.js')

describe('SM', function () {

  it('', function(){
    var alice = new SM('arlo', '123', '456', '789')
    var bob = new SM('arlo', '123', '456', '789')
    alice.initiate(bob.receiveMsg)
  })

})