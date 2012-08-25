[Off-the Record Messaging Protocol](http://www.cypherpunks.ca/otr/) in JavaScript
==================================================

[![Build Status](https://secure.travis-ci.org/arlolra/otr.png?branch=master)](http://travis-ci.org/arlolra/otr)

---

###Warning

This library hasn't been properly vetted by security researchers. Do not use
in life and death situations!

`Math.random()` is replaced by `seedrandom.js`, seeded with either `window.crypto.getRandomValues()` in the [browser](https://developer.mozilla.org/en-US/docs/DOM/window.crypto.getRandomValues), or `crypto.randomBytes()` in [node.js](http://nodejs.org/api/crypto.html#crypto_crypto_randombytes_size_callback).

---

###Install

Include the build files on the page,

    <!-- Load dependencies -->
    <script src="build/dep/seedrandom.js"></script>
    <script src="build/dep/bigint.js"></script>
    <script src="build/dep/crypto.js"></script>

    <!-- Load otr.js or otr.min.js -->
    <script src="build/otr.min.js"></script>

Here's an [example](https://github.com/arlolra/otr/blob/master/test/browser.html) use in the browser.

Although this is a client library, it can be used [on the server](https://github.com/arlolra/otr/blob/master/test/xmpp.js).

    npm install otr

---

###Usage

**Initial setup**: Compute your long-lived key beforehand. Currently this is
expensive and can take several seconds.

    // precompute your DSA key
    var myKey = new DSA.Key()

For each user you're communicating with, instantiate an OTR object.

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

**Going encrypted**: Initially, messages are sent in plaintext. To manually
initiate the authenticated key exchange.

    buddyList.userA.sendQueryMsg()

Alternatively, one can set the policy `REQUIRE_ENCRYPTION` and send a plaintext
message. This will store the message, initiate the authentication and then,
upon success, send it out.

    buddyList.userA.REQUIRE_ENCRYPTION = true
    buddyList.userA.sendMsg('My plaintext message to be encrypted.')


Another policy, `SEND_WHITESPACE_TAG`, will append tags to plaintext messages,
indicating a willingness to speak OTR. If the recipient in turn has set the
policy `WHITESPACE_START_AKE`, the AKE will be initiated.

---

###Policies

To be set on a per-correspondent basis. The defaults are as follows:

    // Allow version 2 of the OTR protocol to be used.
    ALLOW_V2 = true

    // Refuse to send unencrypted messages.
    REQUIRE_ENCRYPTION = false

    // Advertise your support of OTR using the whitespace tag.
    SEND_WHITESPACE_TAG = false

    // Start the OTR AKE when you receive a whitespace tag.
    WHITESPACE_START_AKE = false

    // Start the OTR AKE when you receive an OTR Error Message.
    ERROR_START_AKE = false

---

###Links

Spec:

- http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html
- See: `specs/`

Using:

- [crypto-js](http://code.google.com/p/crypto-js/)
- [bigint.js](http://leemon.com/crypto/BigInt.html)
- [seedrandom.js](http://davidbau.com/archives/2010/01/30/random_seeds_coded_hints_and_quintillions.html)

---

###License

LGPL. Mainly because that's what [libotr](http://www.cypherpunks.ca/otr/) is using.