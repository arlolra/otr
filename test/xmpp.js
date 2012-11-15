var xmpp = require('simple-xmpp')
  , OTR  = require('../index.js').OTR
  , keys = require('./spec/unit/data/keys.js')

var from = ''

function ui(err, msg) {
  if (err) console.log('err: ' + err)
  else console.log('ui: ' + msg)
}

function cb(msg) {
  xmpp.send(from, msg)
}

function smcb(type, data) {
  switch (type) {
    case 'question':
      console.log(data)
      otr.smpSecret('cryptocat')
      break
    case 'abort':
      console.log('aborted')
      break
    case 'trust':
      console.log('trust')
      console.log(otr.trust)
      break
  }
}

var otr = new OTR(keys.userA, ui, cb, {
    fragment_size: 200
  , send_interval: 200
  , smcb: smcb
  , debug: true
})

xmpp.on('online', function() {
  console.log('Yes, I\'m connected!')
  otr.sendQueryMsg()
})

xmpp.on('chat', function(from, message) {
  otr.receiveMsg(message)
})

xmpp.on('error', function(err) {
  console.error(err)
})

xmpp.connect({
  jid      : '',
  password : '',
  host     : 'talk.google.com',
  port     : 5222
})