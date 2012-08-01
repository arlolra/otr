/*global describe before it */

var assert = require('assert')
  , OTR = require('../../../otr.js')
  , DSA = require('../../../dsa.js')

describe('OTR', function () {

  var UAkey, UBkey
  before(function(){
    UAkey = new DSA.Key()
    UBkey = new DSA.Key()
  })

  it('should initiate a new OTR object', function () {
    var userA = new OTR(UAkey)
  })

})