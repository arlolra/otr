var assert = require('assert')
  , SM = require('../sm.js')

describe('SM', function(){
  it('', function(){
    var alice = new SM('arlo')
    var bob = new SM('arlo')

    alice.initiate(bob.receiveMsg)
  });
});
