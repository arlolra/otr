Off-the Record Messaging Protocol v2 in JavaScript
==================================================

[![Build Status](https://secure.travis-ci.org/arlolra/otr.png?branch=master)](http://travis-ci.org/arlolra/otr)

This is obviously still a WIP.

---

###Proposed Usage

**Initial setup**: Compute your long-lived key beforehand. Currently this is
expensive and can take upwards of half a second. For each user you're
communicating with, instantiate an OTR object.

	var OTR = require('otr')
	  , DSA = require('dsa')

	var myKey = new DSA.Key()

	var buddyList = {
		  'userA': new OTR(myKey)
		, 'userB' new OTR(myKey)
	}

**New message from userA received**: Pass the received message to the `receiveMsg`
method along with two callbacks, the first to display parsed messages to the ui,
the second for OTR's automatic responses to AKE, SM, etc.

	var rcvmsg = "Message from userA."
	buddyList.userA.receiveMsg(rcvmsg, uicb, retcb)

**Send a message to userA**: Pass the message to the `sendMsg` method with a
callback for OTR to ship the outgoing encoded message.

	var newmsg = "Message to userA."
	buddyList.userA.sendMsg(newmsg, retcb)

---

Spec: http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html

Using:

- http://code.google.com/p/crypto-js/
- http://leemon.com/crypto/BigInt.html