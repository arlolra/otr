/*global describe it */
var assert = require('assert')
  , keys = require('./data/keys.js')
  , CONST = require('../../../lib/const.js')
  , HLP = require('../../../lib/helpers.js')
  , Parse = require('../../../lib/parse.js')
  , OTR = require('../../../lib/otr.js')

describe('OTR', function () {
  "use strict";

  it('should initiate a new OTR object', function () {
    new OTR({ priv: keys.userA })
  })

  it('should generate an instance tag', function () {
    var tag = HLP.readLen(OTR.makeInstanceTag())
    assert.ok(tag >= 0x00000100)
    assert.ok(tag <= 0xffffffff)
  })

  it('should initiate AKE', function (done) {
    var userB = new OTR({ priv: keys.userB })
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) {
      msg = Parse.parseMsg(userB, msg)
      assert.equal('\x02', msg.type, 'Message type.')
      assert.equal('\x00\x02', msg.version, 'Message version.')
      done()
    })
    // query otr
    userA.receiveMsg('?OTR?v2?')
  })

  it('should query with version two', function (done) {
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) {
      assert.equal('?OTRv2?', msg, msg)
      done()
    })
    userA.ALLOW_V3 = false
    userA.sendQueryMsg()
  })

  it('should query with version three', function (done) {
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) {
      assert.equal('?OTRv3?', msg, msg)
      done()
    })
    userA.ALLOW_V2 = false
    userA.sendQueryMsg()
  })

  it('should query with versions two and three', function (done) {
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) {
      assert.equal('?OTRv23?', msg, msg)
      done()
    })
    userA.sendQueryMsg()
  })

  it('should not send the whitespace tags', function (done) {
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) {
      assert.ok(!~msg.indexOf(CONST.WHITESPACE_TAG))
      assert.ok(!~msg.indexOf(CONST.WHITESPACE_TAG_V2))
      done()
    })
    userA.SEND_WHITESPACE_TAG = false
    userA.sendMsg('hi')
  })

  it('should send the whitespace tags', function (done) {
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) {
      assert.ok(~msg.indexOf(CONST.WHITESPACE_TAG))
      assert.ok(~msg.indexOf(CONST.WHITESPACE_TAG_V2))
      assert.ok(~msg.indexOf(CONST.WHITESPACE_TAG_V3))
      done()
    })
    userA.SEND_WHITESPACE_TAG = true
    userA.sendMsg('hi')
  })

  it('plaintext does not start ake', function (done) {
    var userB = new OTR({ priv: keys.userB })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('ui', function (msg, enc) {
      assert.equal('hi', msg)
      assert.ok(!enc)
      assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
      assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
      done()
    })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR({ priv: keys.userA })
    userA.on('error', function (err) { assert.ifError(err) })
    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_INIT) {
        assert.fail("Ake init.")
      }
    })
    userA.on('io', userB.receiveMsg)
    userB.WHITESPACE_START_AKE = true
    userA.sendMsg('hi')
  })

  it('whitespace start ake', function (done) {
    var userB = new OTR({ priv: keys.userB })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('ui', function (msg) { assert.equal('hi', msg) })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('status', function (state) {
      if (state === CONST.STATUS_AKE_INIT) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
      } else if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
        done()
      }
    })
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    userB.WHITESPACE_START_AKE = true
    userA.SEND_WHITESPACE_TAG = true
    userA.sendMsg('hi')
  })

  it('should go through the ake dance', function (done) {
    var userA, userB, counter = 0
    var err = function (err) { assert.ifError(err) }
    var ui = function (msg) { assert.ok(!msg, msg) }
    var checkstate = function (user) {
      switch (counter) {
        case 0:
        case 1:
          assert.equal(user.authstate, CONST.AUTHSTATE_NONE)
          break
        case 2:
          assert.equal(user.authstate, CONST.AUTHSTATE_AWAITING_DHKEY)
          // This fails sometimes because MPIs use a minimum-length encoding.
          // So, there's a 1/256 chance that first byte is missing.
          // assert.equal(HLP.bigInt2bits(userB.ake.r).length, 128 / 8)
          assert.equal(user.ake.myhashed.length, (256 / 8) + 4)
          break
        case 3:
          assert.equal(user.authstate, CONST.AUTHSTATE_AWAITING_REVEALSIG)
          // Occasionally fails for the same reason as above (195 == 196)
          // assert.equal(user.ake.encrypted.length, 192 + 4)
          assert.equal(user.ake.hashed.length, 256 / 8)
          break
        case 4:
          assert.equal(user.authstate, CONST.AUTHSTATE_AWAITING_SIG)
          // Same, fails (191 == 192).
          // assert.equal(user.ake.their_y.length, 192)
          assert.equal(user.ake.ssid.length, 64 / 8)
          assert.equal(user.ake.c_prime.length, 128 / 8)
          assert.equal(user.ake.m1_prime.length, 256 / 8)
          assert.equal(user.ake.m2_prime.length, 256 / 8)
          // These are nulled out.
          // assert.equal(user.ake.c.length, 128 / 8)
          // assert.equal(user.ake.m1.length, 256 / 8)
          // assert.equal(user.ake.m2.length, 256 / 8)
          break
      }
      counter++
    }
    userA = new OTR({ priv: keys.userA })
    userA.on('ui', ui)
    userA.on('error', err)
    userA.on('io', function (msg) {
      checkstate(userB)
      userB.receiveMsg(msg)
    })
    userB = new OTR({ priv: keys.userB })
    userB.on('ui', ui)
    userB.on('error', err)
    userB.on('io', function (msg) {
      checkstate(userA)
      userA.receiveMsg(msg)
    })

    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')

    userA.sendQueryMsg()  // ask to initiate ake

    userA.on('status', function (yay) {
      if (yay === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        done()
      }
    })
  })

  it('v2, should go through the ake dance', function (done) {
    var err = function (err) { assert.ifError(err) }
    var ui = function (msg) { assert.ok(!msg, msg) }
    var userA = new OTR({ priv: keys.userA })
    userA.on('ui', ui)
    userA.on('error', err)
    userA.on('io', function (msg) {
      userB.receiveMsg(msg)
    })
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', ui)
    userB.on('error', err)
    userB.on('io', function (msg) {
      userA.receiveMsg(msg)
    })
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    userA.ALLOW_V2 = true
    userA.ALLOW_V3 = false
    userA.ALLOW_V2 = true
    userB.ALLOW_V3 = false
    userA.sendQueryMsg()

    userA.on('status', function (yay) {
      if (yay === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        done()
      }
    })
  })

  it('should not go through the ake dance', function (done) {
    var err = function (err) { assert.ifError(err) }
    var ui = function (msg) { assert.ok(!msg, msg) }
    var userA = new OTR({ priv: keys.userA })
    userA.on('ui', ui)
    userA.on('error', err)
    userA.on('io', function (msg) {
      userB.receiveMsg(msg)
    })
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', ui)
    userB.on('error', function (err) {
      assert.equal(err, "OTR conversation requested, but no compatible protocol version found.")
      assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
      assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
      done()
    })
    userB.on('io', function (msg) {
      userA.receiveMsg(msg)
    })
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    userA.ALLOW_V2 = false
    userA.ALLOW_V3 = true
    userB.ALLOW_V2 = true
    userB.ALLOW_V3 = false
    userA.sendQueryMsg()
  })

  it('should receive an encrypted message', function (done) {
    this.timeout(5000)

    var msgs = [
      'Hope this works.',
      'Second message.', 'Third!', '4', '5', '6', '7',
      '8888888888888888888'
    ]
    var counter = 0
    var ui = function (msg) {
      assert.equal(msgs[counter++], msg, 'Encrypted message.')
      if (counter > 7) done()
      else this.sendMsg(msgs[counter])
    }
    var err = function (err) { assert.ifError(err) } 
    var io = function (msg) { userB.receiveMsg(msg) }
    var userA = new OTR({ priv: keys.userA })
    userA.on('ui', ui.bind(userA))
    userA.on('io', io)
    userA.on('error', err)
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', ui.bind(userB))
    userB.on('error', err)
    userB.on('io', userA.receiveMsg)
    userA.sendQueryMsg()
    userB.on('status', function (yay) {
      if (yay === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
        userB.sendMsg(msgs[counter])
      }
    })
  })

  it('should send v2 fragments', function (done) {
    this.timeout(5000)

    var msgs = [
        'Hope this works.'
      , 'Second message.'
      , 'This is a bit of a longer message.'
      , 'Some messages can be quite long and must be fragmented over several pieces.'
      , 'Lalalala alal allaallal alal al alalal alalaaall  lal lal la lal ala  al ala l al a al al al alalalalal alalal  a lal la aal ala lalala l lala lal lala lal la l  alal lalaall la lal la'
    ]
    var counter = 0

    var userA, userB
    var ui = function (ind) {
      return function (msg) {
        var u = users[ind]
        assert.equal(u.u.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Message state unencrypted. Msg: ' + msg)
        assert.equal(u.m[u.c++], msg, 'Encrypted message: ' + msg)
        if (++counter === msgs.length) done()
      }
    }

    userA = new OTR({
        priv: keys.userA
      , fragment_size: 200
      , send_interval: 40
    })
    userA.on('io', function (msg) { userB.receiveMsg(msg) })
    userA.on('ui', ui(0))
    userA.on('error', function (err) { assert.ifError(err) })

    userB = new OTR({
        priv: keys.userB
      , send_interval: 20
    })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('ui', ui(1))
    userB.on('error', function (err) { assert.ifError(err) })

    userA.ALLOW_V2 = true
    userA.ALLOW_V3 = false
    userB.ALLOW_V2 = true
    userB.ALLOW_V3 = false
    userA.REQUIRE_ENCRYPTION = true
    userB.REQUIRE_ENCRYPTION = true

    var ind, users = [
        { u: userA, m: [], c: 0 }
      , { u: userB, m: [], c: 0 }
    ]
    msgs.forEach(function (m) {
      ind = Math.floor(Math.random() * 2)  // assign the messages randomly
      users[ind ? 0 : 1].m.push(m)  // expect the other user to receive it
      users[ind].u.sendMsg(m)
    })
  })

  it('should send v3 fragments', function (done) {
    this.timeout(5000)

    var msgs = [
        'Hope this works.'
      , 'Second message.'
      , 'This is a bit of a longer message.'
      , 'Some messages can be quite long and must be fragmented over several pieces.'
      , 'Lalalala alal allaallal alal al alalal alalaaall  lal lal la lal ala  al ala l al a al al al alalalalal alalal  a lal la aal ala lalala l lala lal lala lal la l  alal lalaall la lal la'
    ]
    var counter = 0

    var userA, userB
    var ui = function (ind) {
      return function (msg) {
        var u = users[ind]
        assert.equal(u.u.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Message state unencrypted. Msg: ' + msg)
        assert.equal(u.m[u.c++], msg, 'Encrypted message: ' + msg)
        if (++counter === msgs.length) done()
      }
    }

    userA = new OTR({
        fragment_size: 200
      , send_interval: 40
      , priv: keys.userA
    })
    userA.on('io', function (msg) { userB.receiveMsg(msg) })
    userA.on('ui', ui(0))
    userA.on('error', function (err) { assert.ifError(err) })

    userB = new OTR({
        send_interval: 20
      , priv: keys.userB
    })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('ui', ui(1))
    userB.on('error', function (err) { assert.ifError(err) })

    userA.ALLOW_V2 = false
    userA.ALLOW_V3 = true
    userB.ALLOW_V2 = false
    userB.ALLOW_V3 = true
    userA.REQUIRE_ENCRYPTION = true
    userB.REQUIRE_ENCRYPTION = true

    var ind, users = [
        { u: userA, m: [], c: 0 }
      , { u: userB, m: [], c: 0 }
    ]
    msgs.forEach(function (m) {
      ind = Math.floor(Math.random() * 2)  // assign the messages randomly
      users[ind ? 0 : 1].m.push(m)  // expect the other user to receive it
      users[ind].u.sendMsg(m)
    })
  })

  it('should ignore messages with diff instance tags', function (done) {
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', function (msg) { assert.ok(!msg, msg) })
    userB.on('error', function (err, severity) {
      assert.equal(severity, 'warn')
    })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    userA.sendQueryMsg()
    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        userA.their_instance_tag = OTR.makeInstanceTag()
        userA.sendMsg('hi')
        // not great ... assume 'hi' should be ignored in less that 200ms
        setTimeout(function () { done() }, 200)
      }
    })
  })

  it('should send utf8 data', function (done) {
    var m = 'hello يا هلا يا حبيبي خذني إلى القمر'
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', function (msg) {
      assert.equal(m, msg, msg)
      done()
    })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    userA.sendQueryMsg()
    userA.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        userA.sendMsg(m)
      }
    })
  })

  it('should send a plaintext message', function (done) {
    var m = 'test some german characters äöüß'
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', function (msg) {
      assert.equal(m, msg, msg)
      done()
    })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('error', function (err) { assert.ifError(err) })
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    userA.sendMsg(m)
  })

  it('should send an encrypted message when required', function (done) {
    var m = 'test some german characters äöüß'
    var userB = new OTR({ priv: keys.userB })
    userB.on('ui', function (msg) {
      assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
      assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
      assert.equal(m, msg, msg)
      done()
    })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    userA.REQUIRE_ENCRYPTION = true
    userA.sendMsg(m)
  })

  it('disconnect when receiving a type 1 TLV', function (done) {
    var userB = new OTR({ priv: keys.userB })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
        userA.endOtr()
      } else if (state === CONST.STATUS_END_OTR) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
        assert.equal(userB.msgstate, CONST.MSGSTATE_FINISHED)
        done()
      }
    })

    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
    userA.sendQueryMsg()
  })

  it('callback after disconnect msg sent', function (done) {
    var userB = new OTR({ priv: keys.userB })
    var sent = false
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
        userA.endOtr(function () {
          assert.ok(sent)
          done()
        })
      } else if (state === CONST.STATUS_END_OTR) {
        assert.equal(userB.msgstate, CONST.MSGSTATE_FINISHED)
        sent = true
      }
    })

    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
    userA.sendQueryMsg()
  })

  it('should confirm extra symmetric keys', function (done) {
    var key, filename = 'testfile!@#$äöüß.zip'

    var userB = new OTR({ priv: keys.userB })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
        userB.sendFile(filename)
      }
    })
    userB.on('file', function (type, keyB, fn) {
      assert.equal(type, 'send')
      assert.equal(filename, fn)
      key = keyB
    })

    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)
    userA.on('file', function (type, keyA, fn) {
      assert.equal(type, 'receive')
      assert.equal(filename, fn)
      assert.equal(key, keyA)
      done()
    })
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
    userA.sendQueryMsg()
  })

  it('should err when encrypted and rcving a plaintext message', function (done) {
    var m = 'here we go now here we go now'

    var userB = new OTR({ priv: keys.userB })
    userB.on('status', function (state) {
      if (state === CONST.STATUS_AKE_SUCCESS) {
        assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
        assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
        // send a plaintext msg w/ internal api
        // don't do this
        userB.io(m)
      }
    })
    userB.on('error', function (err) { assert.ifError(err) })
    userB.on('io', function (msg) { userA.receiveMsg(msg) })

    var userA = new OTR({ priv: keys.userA })
    userA.on('error', function (err) {
      assert.ok(err, "We got an error.")
      done()
    })
    userA.on('io', userB.receiveMsg)
    userA.on('ui', function (msg, enc) {
      assert.ok(msg)
      assert.ifError(enc)
    })

    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
    userA.sendQueryMsg()
  })

  it('should err when require encrypted and rcving a plaintext', function (done) {
    var m = 'here we go now here we go now'

    var userB = new OTR({ priv: keys.userB })
    userB.REQUIRE_ENCRYPTION = true
    userB.on('ui', function (msg, enc) {
      assert.ok(msg)
      assert.ifError(enc)
    })
    userB.on('error', function (err) {
      assert.ok(err, "We got an error.")
      done()
    })

    var userA = new OTR({ priv: keys.userA })
    userA.on('io', userB.receiveMsg)

    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
    userA.sendMsg(m)
  })
  
  it('should passthrough meta data in plaintext mode', function(done) {
     var m1 = 'text message'
     var m2 = 'meta data'

     var userA = new OTR({ priv: keys.userA })
     userA.on('io', function (msg, meta) {
        assert.equal(msg, m1)
        assert.equal(meta, m2)
        done()
     })

     userA.sendMsg(m1, m2)        
  })
  
  it('should passthrough meta data in encrypted mode', function(done) {
     var m1 = 'text message'
     var m2 = 'meta data'

     var userA = new OTR({ priv: keys.userA })
     var userB = new OTR({ priv: keys.userB })
     userA.on('io', function (msg, meta) {
        if (userA.msgstate === CONST.MSGSTATE_ENCRYPTED){
           assert.equal(meta, m2)
           done()
        }
        userB.receiveMsg(msg)
     })
     userA.on('status', function(state){ 
        if (state === CONST.STATUS_AKE_SUCCESS) {
           userA.sendMsg(m1, m2)
        }
     })
     userB.on('io', userA.receiveMsg)

     userB.sendQueryMsg()
  })
  
  it('should passthrough meta data for stored messages', function(done) {
     var m1 = 'text message'
     var m2 = 'meta data'

     var userA = new OTR({ priv: keys.userA })
     var userB = new OTR({ priv: keys.userB })
     userA.msgstate = CONST.MSGSTATE_FINISHED;
     userA.on('io', function (msg, meta) {
        if (userA.msgstate === CONST.MSGSTATE_ENCRYPTED){
           assert.equal(meta, m2)
           done()
        }
        userB.receiveMsg(msg)
     })
     userB.on('io', userA.receiveMsg)

     userA.sendMsg(m1, m2)
     userB.sendQueryMsg()   
  })

  it('should passthrough meta data for fragmented messages', function(done) {
     var m1 = 'Lalalala alal allaallal alal al alalal alalaaall  lal lal la lal ala  al ala l al a al al al alalalalal alalal  a lal la aal ala lalala l lala lal lala lal la l  alal lalaall la lal la'
     var m2 = 'meta data'

     var userA = new OTR({
          priv: keys.userA
        , fragment_size: 200 
        , send_interval: 40
        })
     var userB = new OTR({ priv: keys.userB, send_interval: 20 })
     userA.on('io', function (msg, meta) {
        if (userA.msgstate === CONST.MSGSTATE_ENCRYPTED){
           assert.equal(meta, m2)
           if (msg.replace(/^\?OTR[^,]+,(\d),(\d)/, '$1') == msg.replace(/^\?OTR[^,]+,(\d),(\d)/, '$2'))
              done()
        }
        userB.receiveMsg(msg)
     })
     userA.on('status', function(state){ 
        if (state === CONST.STATUS_AKE_SUCCESS) {
           userA.sendMsg(m1, m2)
        }
     })
     userB.on('io', userA.receiveMsg)
     
     userB.sendQueryMsg() 
  })

  it('should check for DH pubkey equality before skipping key replacement', function (done) {
    this.timeout(5000)
    // issue #47

    var err = function (err) { assert.ifError(err) }

    var userA = new OTR({ priv: keys.userA })
    userA.on('io', function (msg) { userB.receiveMsg(msg) })
    userA.on('error', err)

    var bIT = OTR.makeInstanceTag()

    var userB = new OTR({ priv: keys.userB, instance_tag: bIT })
    userB.on('io', userA.receiveMsg)
    userB.on('error', err)
    var rcvd = 0
    userB.on('ui', function (msg, enc) {
      assert.ok(enc)
      rcvd += 1
      if (rcvd === 2) {
        rcvd = 0

        // userB crashed; start over
        userB = new OTR({ priv: keys.userB, instance_tag: bIT })
        userB.on('io', userA.receiveMsg)
        userB.on('error', err)
        userB.on('ui', function (msg, enc) {
          assert.ok(enc)
          rcvd += 1
          if (rcvd === 2) {
            done()
          }
        })
        userB.sendQueryMsg()

      }
    })

    userA.on('status', function (state) {
      if (state === OTR.CONST.STATUS_AKE_SUCCESS) {
        userA.sendMsg("Amsg1 to B1")
        userA.sendMsg("Amsg2 to B1")
      }
    })
    userA.sendQueryMsg()

  })

  it('should passthrough meta data for received message', function (done) {
     var m1 = 'text message'
     var m2 = 'meta data'

     var userA = new OTR({ priv: keys.userA })
     userA.on('ui', function (msg, encrypted, meta) {
        assert.equal(msg, m1)
        assert.equal(meta, m2)
        done()
     })

     userA.receiveMsg(m1, m2)
  })

})