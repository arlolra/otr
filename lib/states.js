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

    // whitespace tags
    , WHITESPACE_TAG    : '\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
    , WHITESPACE_TAG_V2 : '\x20\x20\x09\x09\x20\x20\x09\x20'

    // otr tags
    , OTR_TAG       : '?OTR'
    , OTR_VERSION_2 : '\x00\x02'

  }

  if (typeof exports !== 'undefined') {
    module.exports = STATES
  } else {
    root.STATES = STATES
  }

}).call(this)