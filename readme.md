Off-the Record Messaging Protocol v2 in JavaScript
==================================================

[![Build Status](https://secure.travis-ci.org/arlolra/otr.png?branch=master)](http://travis-ci.org/arlolra/otr)

---

###Warning

Replace `Math.random()`

See: [bigint.js](https://github.com/arlolra/otr/blob/9a1329b0d2d673bae714d4bc5b25109952ed0106/vendor/bigint.js#L62-63)

---

###Install

For now, see [this example](https://github.com/arlolra/otr/blob/master/test/browser.html) for use in the browser.

Although this is a client library, it can be used [on the server](https://github.com/arlolra/otr/blob/master/test/xmpp.js). Just:

  npm install otr

---

###Usage

**Initial setup**: Compute your long-lived key beforehand. Currently this is
expensive and can take upwards of half a second. For each user you're
communicating with, instantiate an OTR object.

	var OTR = require('otr')
	  , DSA = require('dsa')

	var myKey = new DSA.Key()

	// provide some callbacks to otr
	var uicb = function (msg) {
		console.log("message to display to the user: " + msg)
	}
	var iocb = function (msg) {
		console.log("message to send to buddy: " + msg)
	} 

	var buddyList = {
		  'userA': new OTR(myKey, uicb, iocb)
		, 'userB' new OTR(myKey uicb, iocb)
	}

**New message from userA received**: Pass the received message to the `receiveMsg`
method.

	var rcvmsg = "Message from userA."
	buddyList.userA.receiveMsg(rcvmsg)

**Send a message to userA**: Pass the message to the `sendMsg` method.

	var newmsg = "Message to userA."
	buddyList.userA.sendMsg(newmsg)

---

Spec: http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html

Using:

- http://code.google.com/p/crypto-js/
- http://leemon.com/crypto/BigInt.html