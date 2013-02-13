/*global describe before it */
var assert = require('assert')
  , keys = require('./data/keys.js')
  , CONST = require('../../../lib/const.js')
  , HLP = require('../../../lib/helpers.js')
  , Parse = require('../../../lib/parse.js')
  , OTR = require('../../../lib/otr.js')

describe('OTR', function () {

  var cb = function () {}

  it('should initiate a new OTR object', function () {
    var userA = new OTR({ priv: keys.userA })
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

  it('should go through the ake dance', function () {
    var userA, userB, counter = 0
    var ui = function (err, msg) {
      assert.ifError(err)
      assert.ok(!msg, msg)
    }
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
          assert.equal(user.ake.c.length, 128 / 8)
          assert.equal(user.ake.c_prime.length, 128 / 8)
          assert.equal(user.ake.m1.length, 256 / 8)
          assert.equal(user.ake.m2.length, 256 / 8)
          assert.equal(user.ake.m1_prime.length, 256 / 8)
          assert.equal(user.ake.m2_prime.length, 256 / 8)
          break
      }
      counter++
    }
    userA = new OTR(keys.userA, ui, function (msg) {
      checkstate(userB)
      userB.receiveMsg(msg)
    })
    userB = new OTR(keys.userB, ui, function (msg) {
      checkstate(userA)
      userA.receiveMsg(msg)
    })

    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')

    userA.sendQueryMsg()  // ask to initiate ake

    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
  })

it('should go through the ake dance, v2', function () {
    var ui = function (err, msg) {
      assert.ifError(err)
      assert.ok(!msg, msg)
    }
    var userA = new OTR(keys.userA, ui, function (msg) {
      userB.receiveMsg(msg)
    })
    var userB = new OTR(keys.userB, ui, function (msg) {
      userA.receiveMsg(msg)
    })
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    userA.ALLOW_V2 = true
    userA.ALLOW_V3 = false
    userA.ALLOW_V2 = true
    userB.ALLOW_V3 = false
    userA.sendQueryMsg()
    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Encrypted')
  })

  it('should not go through the ake dance', function () {
    var ui = function (err, msg) {
      assert.ifError(err)
      assert.ok(!msg, msg)
    }
    var userA = new OTR(keys.userA, ui, function (msg) {
      userB.receiveMsg(msg)
    })
    var userB = new OTR(keys.userB, ui, function (msg) {
      userA.receiveMsg(msg)
    })
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    userA.ALLOW_V2 = false
    userA.ALLOW_V3 = true
    userB.ALLOW_V2 = true
    userB.ALLOW_V3 = false
    userA.sendQueryMsg()
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT, 'Plaintext')
  })

  it('should receive an encrypted message', function () {
    var msgs = ['Hope this works.', 'Second message.', 'Third!', '4', '5', '6', '7', '8888888888888888888']
    var counter = 0

    var userA, userB
    var ui = function (err, msg) {
      assert.ifError(err)
      assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
      assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
      assert.equal(msgs[counter++], msg, 'Encrypted message.')
    }
    var io = function (msg) { userB.receiveMsg(msg) }
    userA = new OTR(keys.userA, ui, io)
    userB = new OTR(keys.userB, ui, userA.receiveMsg)
    userA.sendQueryMsg()
    userB.sendMsg(msgs[counter])
    assert.equal(counter, 1)
    userB.sendMsg(msgs[counter])
    assert.equal(counter, 2)
    userA.sendMsg(msgs[counter])
    assert.equal(counter, 3)
    userA.sendMsg(msgs[counter])
    assert.equal(counter, 4)
    userA.sendMsg(msgs[counter])
    assert.equal(counter, 5)
    userB.sendMsg(msgs[counter])
    assert.equal(counter, 6)
    userB.sendMsg(msgs[counter])
    assert.equal(counter, 7)
    userA.sendMsg(msgs[counter])
    assert.equal(counter, 8)
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
      return function (err, msg) {
        assert.ifError(err)
        var u = users[ind]
        assert.equal(u.u.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Message state unencrypted. Msg: ' + msg)
        assert.equal(u.m[u.c++], msg, 'Encrypted message: ' + msg)
        if (++counter === msgs.length) done()
      }
    }
    var io = function (msg) { userB.receiveMsg(msg) }

    userA = new OTR(keys.userA, ui(0), io, { fragment_size: 200, send_interval: 40 })
    userB = new OTR(keys.userB, ui(1), userA.receiveMsg, { send_interval: 20 })

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
    msgs.forEach(function (m, i) {
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
      return function (err, msg) {
        assert.ifError(err)
        var u = users[ind]
        assert.equal(u.u.msgstate, CONST.MSGSTATE_ENCRYPTED, 'Message state unencrypted. Msg: ' + msg)
        assert.equal(u.m[u.c++], msg, 'Encrypted message: ' + msg)
        if (++counter === msgs.length) done()
      }
    }
    var io = function (msg) { userB.receiveMsg(msg) }

    userA = new OTR(keys.userA, ui(0), io, { fragment_size: 200, send_interval: 40 })
    userB = new OTR(keys.userB, ui(1), userA.receiveMsg, { send_interval: 20 })

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
    msgs.forEach(function (m, i) {
      ind = Math.floor(Math.random() * 2)  // assign the messages randomly
      users[ind ? 0 : 1].m.push(m)  // expect the other user to receive it
      users[ind].u.sendMsg(m)
    })
  })

  it('should ignore messages with diff instance tags', function () {
    var userB = new OTR(keys.userB, function (err, msg) {
      assert.ifError(err)
      assert.ok(!msg, msg)
    }, function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR(keys.userA, cb, userB.receiveMsg)
    userA.sendQueryMsg()
    userA.their_instance_tag = OTR.makeInstanceTag()
    userA.sendMsg('hi')
  })

  it('should send utf8 data', function () {
    var m = 'hello يا هلا يا حبيبي خذني إلى القمر'
    var userB = new OTR(keys.userB, function (err, msg) {
      assert.ifError(err)
      assert.equal(m, msg, msg)
    }, function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR(keys.userA, cb, userB.receiveMsg)
    userA.sendQueryMsg()
    userA.sendMsg(m)
  })

  it('should send a plaintext message', function () {
    var m = 'test some german characters äöüß'
    var userB = new OTR(keys.userB, function (err, msg) {
      assert.ifError(err)
      assert.equal(m, msg, msg)
    }, function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR(keys.userA, cb, userB.receiveMsg)
    userA.sendMsg(m)
  })

  it('should send an encrypted message when required', function () {
    var m = 'test some german characters äöüß'
    var userB = new OTR(keys.userB, function (err, msg) {
      assert.ifError(err)
      assert.equal(m, msg, msg)
    }, function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR(keys.userA, cb, userB.receiveMsg)
    userA.REQUIRE_ENCRYPTION = true
    userA.sendMsg(m)
  })

  it('disconnect when receiving a type 1 TLV', function () {
    var userB = new OTR(keys.userB, function (err, msg) {
      assert.ifError(err)
      // assert.equal(m, msg, msg)
    }, function (msg) { userA.receiveMsg(msg) })
    var userA = new OTR(keys.userA, cb, userB.receiveMsg)
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_PLAINTEXT)
    userA.sendQueryMsg()
    assert.equal(userA.msgstate, CONST.MSGSTATE_ENCRYPTED)
    assert.equal(userB.msgstate, CONST.MSGSTATE_ENCRYPTED)
    userA.endOtr()
    assert.equal(userA.msgstate, CONST.MSGSTATE_PLAINTEXT)
    assert.equal(userB.msgstate, CONST.MSGSTATE_FINISHED)
  })

})