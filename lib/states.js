;(function () {

  var root = this

  var STATES = {

    // otr message states
      MSGSTATE_PLAINTEXT : 0
    , MSGSTATE_ENCRYPTED : 1
    , MSGSTATE_FINISHED  : 2

    // otr auth states
    , AUTHSTATE_NONE               : 0
    , AUTHSTATE_AWAITING_DHKEY     : 1
    , AUTHSTATE_AWAITING_REVEALSIG : 2
    , AUTHSTATE_AWAITING_SIG       : 3
    , AUTHSTATE_V1_SETUP           : 4

  }

  if (typeof exports !== 'undefined') {
    module.exports = STATES
  } else {
    root.STATES = STATES
  }

}).call(this)