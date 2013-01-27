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

And then,

    var DSA = require('otr').DSA
    var OTR = require('otr').OTR

---

###Usage

**Initial setup**: Compute your long-lived key beforehand. Currently this is
expensive and can take several seconds.

    // precompute your DSA key
    var myKey = new DSA()

For each user you're communicating with, instantiate an OTR object.

    // provide some callbacks to otr
    var uicb = function (err, msg) {
      if (err) return console.log("error occurred: " + err)
      console.log("message to display to the user: " + msg)
    }
    var iocb = function (msg) {
      console.log("message to send to buddy: " + msg)
    }

    // provide options
    var options = { fragment_size: 140, send_interval: 200 }

    var buddyList = {
        'userA': new OTR(myKey, uicb, iocb, options)
      , 'userB': new OTR(myKey, uicb, iocb, options)
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

**Close private connection**: To end an encrypted communication,

    buddyList.userA.endOtr()

will return the message state to plaintext and notify the correspondent.

**Options**: A dictionary of the current options accepted by the OTR constructor.

    var options = {

      // turn on some debuggin logs
      debug: false,

      // socialist millionaire callback
      smcb: function () {},

      // fragment the message in case of char limits
      fragment_size: 140,

      // ms delay between sending fragmented msgs, avoid rate limits
      send_interval: 200

    }

---

###Policies

To be set on a per-correspondent basis. The defaults are as follows:

    // Allow version 2 or 3 of the OTR protocol to be used.
    ALLOW_V2 = true
    ALLOW_V3 = true

    // Refuse to send unencrypted messages.
    REQUIRE_ENCRYPTION = false

    // Advertise your support of OTR using the whitespace tag.
    SEND_WHITESPACE_TAG = false

    // Start the OTR AKE when you receive a whitespace tag.
    WHITESPACE_START_AKE = false

    // Start the OTR AKE when you receive an OTR Error Message.
    ERROR_START_AKE = false

---

###Instance Tags

These are intended to be persistent and can be precomputed.

    var myTag = OTR.makeInstanceTag()
    var options = { instance_tag: myTag }

    var userA = new OTR(myKey, uicb, iocb, options)
    var userB = new OTR(myKey, uicb, iocb, options)

---

###Fingerprints

OTR public key fingerprints can be obtained as follows:

    // assume you've gone through the ake with userA
    var userA = new OTR(myKey, uicb, iocb, options)

    // for my key, either one of the following
    myKey.fingerprint()
    // or,
    userA.priv.fingerprint()

    // for their key
    userA.their_priv_pk.fingerprint()

---

###Socialist Millionaire Protocol

At any time after establishing encryption, either party can initiate SMP to
detect impersonation or man-in-the-middle attacks. A shared secret,
exchanged through an out-of-band channel prior to starting the conversation,
is required.

    var secret = "ghostbusters"
    buddyList.userA.smpSecret(secret)

A question can be supplied, as a reminder of the shared secret.

    var question = "who are you going to call?"
    buddylist.userA.smpSecret(secret, question)

If you plan on using SMP, as opposed to just allowing fingerprints for
verification, provide on optional callback when initiating OTR,
otherwise a no-opt is fired.

    function smcb(type, data) {
      switch (type) {
        case 'question':
          // call(data) some function with question?
          // return the user supplied data to
          // userA.smpSecret(secret)
          break
        case 'trust':
          // smp completed or aborted
          // check userA.trust and update ui accordingly
          break
        default:
          throw new Error('Unknown type.')
      }
    }

    var options = { smcb: smcb }
    var userA = new OTR(myKey, uicb, iocb, options)

If the protocol successfully runs to completion,

    buddyList.userA.trust === true

---

### Private Keys

To export a private, long-lived key:

    var myKey = new DSA()
    var string = myKey.packPrivate()  // returns a Base64 encoded string

It can then be imported as follows,

    // string = "AAAAAACA4COdKHpU/np9F8EDdnGiJJmc89p ... I9BzTkQduFA7ovXAMY="
    var myKey = DSA.parsePrivate(string)

---

###Links

Spec:

- http://www.cypherpunks.ca/otr/Protocol-v3-4.0.0.html
- http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html
- See: `specs/`

Using:

- [crypto-js](http://code.google.com/p/crypto-js/)
- [bigint.js](http://leemon.com/crypto/BigInt.html)
- [seedrandom.js](http://davidbau.com/archives/2010/01/30/random_seeds_coded_hints_and_quintillions.html)

---

###In The Wild

A sampling of projects that use this library:

- [Cryptocat](https://github.com/cryptocat/cryptocat)
- [Yabasta](https://github.com/jonkri/yabasta)

---

###License

MPL v2.0