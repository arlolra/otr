var xmpp = require('simple-xmpp')
  , OTR  = require('../lib/otr.js')
  , keys = require('./spec/unit/data/keys.js')

var from = ''

function ui(msg) {
  console.log('ui: ' + msg)
}

function cb(msg) {
  xmpp.send(from, msg)
}

var otr = new OTR(keys.userA, ui, cb, {
    fragment_size: 200
  , send_interval: 200
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