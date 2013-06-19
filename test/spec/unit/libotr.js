/*global describe it before */
var spawn = require('child_process').spawn
  , keys = require('./data/keys.js')
  , OTR = require('../../../lib/otr.js')
  , CONST = require('../../../lib/const.js')

// this test is ported from golang
// https://code.google.com/p/go/source/browse/otr/otr_test.go?repo=crypto

// compile test/libotr_test_helper.c against libotr-3.2.0
// output as /tmp/a.out
// see the Makefile

describe('Libotr', function () {
  "use strict";

  var buddy
  before(function () {
    buddy = new OTR({ priv: keys.userA })
  })

  it('should ake and talk with libotr', function (done) {
    this.timeout(10000)

    var cp = spawn('test/libotr_test_helper.out')

    buddy.on('io', function (msg) {
      cp.stdin.write(msg + '\n')
    })

    buddy.on('ui', function (msg) {
      if (msg === "test message") done()
    })

    buddy.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        buddy.sendMsg("Go -> libotr test message")
      }
    })

    cp.stdout.on('data', function (msg) {
      buddy.receiveMsg(msg.toString())
    })

    cp.stderr.on('data', function (err) {
      err = err.toString()

      if (err === "libotr helper started\n") {
        buddy.sendQueryMsg()
        return
      }

      // console.log(err)
    })

    cp.on('exit', function (code) {
      console.log('exited with code: ' + code)
    })

  })

})