[![Build Status](https://travis-ci.org/arlolra/otr.svg?branch=master)](https://travis-ci.org/arlolra/otr)

[Off-the Record Messaging Protocol](http://www.cypherpunks.ca/otr/) in JavaScript
==================================================

### Warning

This library hasn't been properly vetted by security researchers. Do not use
in life and death situations!

### Install

Include the build files on the page,

    <!-- Load dependencies -->
    <script src="build/dep/bigint.js"></script>
    <script src="build/dep/crypto.js"></script>
    <script src="build/dep/eventemitter.js"></script>

    <!-- Load otr.js or otr.min.js -->
    <script src="build/otr.min.js"></script>

Here's an [example](https://github.com/arlolra/otr/blob/master/test/browser.html) use in the browser.

Although this is a client library, it can be used [on the server](https://github.com/arlolra/otr/blob/master/test/xmpp.js).

    npm install otr

And then,

    var DSA = require('otr').DSA
    var OTR = require('otr').OTR

### Build

The contents of `build/` are the result of calling `make build` and are only
updated with releases. Please submit patches against `lib/` and `vendor/`.

### Release

The normal flow for making a release is as follows,

    make test
    // bump the version numbers in package.json / bower.json
    make build
    git changelog  // cleanup the changelog
    git commit -m "bump version"
    git tag -a vX.X.X -m "version X.X.X"
    git push origin master
    git push --tags
    npm publish
    // update github releases and pages

### Usage

**Initial setup**: Compute your long-lived key beforehand. Currently this is
expensive and can take several seconds.

    // precompute your DSA key
    var myKey = new DSA()

For each user you're communicating with, instantiate an OTR object.

    // provide options
    var options = {
        fragment_size: 140
      , send_interval: 200
      , priv: myKey
    }

    var buddy = new OTR(options)

    buddy.on('ui', function (msg, encrypted, meta) {
      console.log("message to display to the user: " + msg)
      // encrypted === true, if the received msg was encrypted
      console.log("(optional) with receiveMsg attached meta data: " + meta)
    })

    buddy.on('io', function (msg, meta) {
      console.log("message to send to buddy: " + msg)
      console.log("(optional) with sendMsg attached meta data: " + meta)
    })

    buddy.on('error', function (err, severity) {
      if (severity === 'error')  // either 'error' or 'warn'
        console.error("error occurred: " + err)
    })

**New message from buddy received**: Pass the received message to the `receiveMsg`
method.

    var rcvmsg = "Message from buddy."
    var meta = "optional some meta data, like delay"
    buddy.receiveMsg(rcvmsg, meta)

**Send a message to buddy**: Pass the message to the `sendMsg` method.

    var newmsg = "Message to userA."
    var meta = "optional some meta data, like message id"
    buddy.sendMsg(newmsg, meta)

**Going encrypted**: Initially, messages are sent in plaintext. To manually
initiate the authenticated key exchange.

    buddy.sendQueryMsg()

Alternatively, one can set the policy `REQUIRE_ENCRYPTION` and send a plaintext
message. This will store the message, initiate the authentication and then,
upon success, send it out.

    buddy.REQUIRE_ENCRYPTION = true
    buddy.sendMsg('My plaintext message to be encrypted.')

Another policy, `SEND_WHITESPACE_TAG`, will append tags to plaintext messages,
indicating a willingness to speak OTR. If the recipient in turn has set the
policy `WHITESPACE_START_AKE`, the AKE will be initiated.

**Close private connection**: To end an encrypted communication session,

    buddy.endOtr(function() {
      // calls back when the 'disconnect' message has been sent
    })

will return the message state to plaintext and notify the correspondent.

**Options**: A dictionary of the current options accepted by the OTR constructor.

    var options = {

      // long-lived private key
      priv: new DSA(),

      // turn on some debuggin logs
      debug: false,

      // fragment the message in case of char limits
      fragment_size: 140,

      // ms delay between sending fragmented msgs, avoid rate limits
      send_interval: 200

    }

### Status

A listener can be attached for status changes. These are non-standard codes,
specific to this OTR library, indicating various things like the AKE success.

    buddy.on('status', function (state) {
      switch (state) {
        case OTR.CONST.STATUS_AKE_SUCCESS:
          // sucessfully ake'd with buddy
          // check if buddy.msgstate === OTR.CONST.MSGSTATE_ENCRYPTED
          break
        case OTR.CONST.STATUS_END_OTR:
          // if buddy.msgstate === OTR.CONST.MSGSTATE_FINISHED
          // inform the user that his correspondent has closed his end
          // of the private connection and the user should do the same
          break
      }
    })

### Policies

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

### Instance Tags

These are intended to be persistent and can be precomputed.

    var myTag = OTR.makeInstanceTag()
    var options = { instance_tag: myTag }

    var buddy = new OTR(options)

### Fingerprints

OTR public key fingerprints can be obtained as follows:

    // assume you've gone through the ake with buddy
    var buddy = new OTR({ priv: myKey })
    // buddy.msgstate === OTR.CONST.MSGSTATE_ENCRYPTED

    // for my key, either one of the following
    myKey.fingerprint()
    // or,
    buddy.priv.fingerprint()

    // for their key
    buddy.their_priv_pk.fingerprint()

### Socialist Millionaire Protocol

At any time after establishing encryption, either party can initiate SMP to
detect impersonation or man-in-the-middle attacks. A shared secret,
exchanged through an out-of-band channel prior to starting the conversation,
is required.

    var secret = "ghostbusters"
    buddy.smpSecret(secret)

A question can be supplied, as a reminder of the shared secret.

    var question = "who are you going to call?"
    buddy.smpSecret(secret, question)

If you plan on using SMP, as opposed to just allowing fingerprints for
verification, provide on optional callback when initiating OTR,
otherwise a no-opt is fired.

    var buddy = new OTR()

    buddy.on('smp', function (type, data, act) {
      switch (type) {
        case 'question':
          // call(data) some function with question?
          // return the user supplied data to
          // userA.smpSecret(secret)
          break
        case 'trust':
          // smp completed
          // check data (true|false) and update ui accordingly
          // act ("asked"|"answered") provides info one who initiated the smp
          break
        case 'abort':
          // smp was aborted. notify the user or update ui
        default:
          throw new Error('Unknown type.')
      }
    })

Both users should run the SMP to establish trust. Further, it should be run each time a partner presents a fresh long-lived key.

### Private Keys

To export a private, long-lived key:

    var myKey = new DSA()
    var string = myKey.packPrivate()  // returns a Base64 encoded string

It can then be imported as follows,

    string = "AAAAAACA4COdKHpU/np9F8EDdnGiJJmc89p ... I9BzTkQduFA7ovXAMY="
    myKey = DSA.parsePrivate(string)

Importing the (somewhat) standard libotr s-expression format works as well,

    // in node.js
    var fs = require('fs')
    string = fs.readFileSync("~/.purple/otr.private_key", 'utf8')

    // leaving out the terminal backslashes needed for multiline strings in js
    string = "(privkeys
      (account
        (name "foo@example.com")
        (protocol prpl-jabber)
        (private-key
          (dsa
            (p #00FC07 ... 2AEFD07A2081#)
            (q #ASD5FF ... LKJDF898DK12#)
            (g #535E3E ... 1E3BC1FC6F26#)
            (y #0AC867 ... 8969009B6ECF#)
            (x #14D034 ... F72D79043216#)
          )
        )
      )
    )"

    myKey = DSA.parsePrivate(string, true)

### Extra Symmetric Key

In version 3 of the protocol, an extra symmetric key is derived during the AKE. This may be used for secure communication over a different channel (e.g., file transfer, voice chat).

    var filename = "test.zip"
    var buddy = new OTR()
    buddy.sendFile(filename)
    buddy.on('file', function (type, key, filename) {
      // type === 'send'
      // key should be used to encrypt filename
      // and sent through a different channel
    })

On the other end,

    var friend = new OTR()
    friend.on('file', function (type, key, filename) {
      // type === 'receive'
      // decrypt filename with key, once received
    })

### WebWorkers

Some support exists for calling computationally expensive work off the main
thread. However, some feedback on these APIs would be appreciated.

    // generate a DSA key in a web worker
    DSA.createInWebWorker(null, function (key) {
			var buddy = new OTR({
				priv: key,
				// setting `smw` to a truthy value will perform the socialist
				// millionaire protocol in a webworker.
				smw: {}
			})
	  })

WebWorkers don't have access to `window.crypto.getRandomValues()`, so they will
need to include Salsa20.

    <script src="build/dep/salsa20.js"></script>

### Links

Spec:

- http://www.cypherpunks.ca/otr/Protocol-v3-4.0.0.html
- http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html
- See: `specs/`

Using:

- [crypto-js](http://code.google.com/p/crypto-js/)
- [bigint.js](http://leemon.com/crypto/BigInt.html)
- [salsa20.js](https://gist.github.com/dchest/4582374)
- [eventemitter.js](https://github.com/Wolfy87/EventEmitter)

### In The Wild

A sampling of projects that use this library:

- [Cryptocat](https://github.com/cryptocat/cryptocat)
- [Yabasta](https://github.com/jonkri/yabasta)
- [Diaspora](https://github.com/sualko/diaspora)
- [Converse.js](https://github.com/jcbrand/converse.js)
- [WebRTCCopy](https://github.com/erbbysam/webRTCCopy)
- [OTRon](https://github.com/osnr/otron)
- [ojsxc (owncloud)](https://github.com/sualko/ojsxc)
- [sjsxc (SOGo)](https://github.com/sualko/sjsxc)
- [LoquiIM](https://loqui.im/)
- [Salut à Toi](http://salut-a-toi.org/) ([Python wrapper][0] for Pyjamas)
- [HackTunnel](https://github.com/devhq-io/hacktunnel)

[0]: http://repos.goffi.org/libervia/file/tip/src/browser/sat_browser/otrjs_wrapper.py

### Donate

Bitcoins: 1BWLnnig89fpn8hCcASd2B1YbfK6j1vtX3

### License

MPL v2.0
