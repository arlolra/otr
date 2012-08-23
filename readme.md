Off-the Record Messaging Protocol v2 in JavaScript
==================================================

[![Build Status](https://secure.travis-ci.org/arlolra/otr.png?branch=master)](http://travis-ci.org/arlolra/otr)

---

###Warning

This library hasn't been properly vetted by security researchers. Do not use
in life and death situations!

`Math.random()` is replaced by `seedrandom.js`, seeded by either `window.crypto.getRandomValues()` in the [browser](https://developer.mozilla.org/en-US/docs/DOM/window.crypto.getRandomValues), or `crypto.randomBytes()` in [node.js](http://nodejs.org/api/crypto.html#crypto_crypto_randombytes_size_callback).

---

###Install

For now, see [this example](https://github.com/arlolra/otr/blob/master/test/browser.html) for use in the browser.

Although this is a client library, it can be used [on the server](https://github.com/arlolra/otr/blob/master/test/xmpp.js).

    npm install otr

---

###Usage

**Initial setup**: Compute your long-lived key beforehand. Currently this is
expensive and can take upwards of half a second. For each user you're
communicating with, instantiate an OTR object.

    var OTR = require('otr')
      , DSA = require('dsa')

    // precompute your DSA key
    var myKey = new DSA.Key()

    // provide some callbacks to otr
    var uicb = function (msg) {
      console.log("message to display to the user: " + msg)
    }
    var iocb = function (msg) {
      console.log("message to send to buddy: " + msg)
    }

    // provide options
    var options = {
        fragment_size: 140  // fragment the message in case of char limits
      , send_interval: 200  // ms delay between sending fragmented msgs, avoid rate limits
    }

    var buddyList = {
        'userA': new OTR(myKey, uicb, iocb, options)
      , 'userB' new OTR(myKey uicb, iocb, options)
    }

**New message from userA received**: Pass the received message to the `receiveMsg`
method.

    var rcvmsg = "Message from userA."
    buddyList.userA.receiveMsg(rcvmsg)

**Send a message to userA**: Pass the message to the `sendMsg` method.

    var newmsg = "Message to userA."
    buddyList.userA.sendMsg(newmsg)

**Going encrypted**: Initially, messages are sent in plaintext. To setup a secure
communication channel, at the moment, one must manually initiate the authenticated
key exchange.

    buddyList.userA.sendQueryMsg()

Alternatively, one can set the policy `REQUIRE_ENCRYPTION` and send a plaintext
message. This will store the message, initiate the authentication and then,
upon success, send it out.

    buddyList.userA.REQUIRE_ENCRYPTION = true
    buddyList.userA.sendMsg('My plaintext message to be encrypted.')

The protocol does specify a policy whereby a plaintext message can be appended
with whitespace tags to indicate ones willingness to speak with OTR, but this
has yet to be implemented. See [issue 13](https://github.com/arlolra/otr/issues/13)
for updates.

---

###Links

Spec: http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html

Using:

- [crypto-js](http://code.google.com/p/crypto-js/)
- [bigint.js](http://leemon.com/crypto/BigInt.html)
- [seedrandom.js](http://davidbau.com/archives/2010/01/30/random_seeds_coded_hints_and_quintillions.html)