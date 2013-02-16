var xmpp = require('simple-xmpp')
  , OTR  = require('../index.js').OTR
  , keys = require('./spec/unit/data/keys.js')

var from = ''

function err(err) {
  console.log('err: ' + err)
}

function ui(msg) {
  console.log('ui: ' + msg)

  if (~msg.indexOf('hello')) {
    otr.smpSecret('cryptocat')
  }
}

function cb(msg) {
  xmpp.send(from, msg)
}

function smp(type, data) {
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

var otr = new OTR({
    fragment_size: 200
  , send_interval: 200
  , debug: true
  , priv: keys.userA
})

otr.on('ui', ui)
otr.on('io', cb)
otr.on('error', err)
otr.on('smp', smp)

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