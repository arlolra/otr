var Crypto = require('./vendor/aes.js')
  , SM = require('./sm.js')

module.exports = OTR

function OTR() {
  if (!(this instanceof OTR)) return new OTR()
  
  
}

OTR.prototype = {

  constructor: OTR,

  sendMsg: function () {
    
  },

  receiveMsg: function () {
    
  } 

}