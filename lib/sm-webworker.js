;(function (root) {
  "use strict";

  root.OTR = {}
  root.crypto = {}

  // default imports
  var imports = [
      'vendor/salsa20.js'
    , 'vendor/bigint.js'
    , 'vendor/crypto.js'
    , 'vendor/eventemitter.js'
    , 'lib/const.js'
    , 'lib/helpers.js'
    , 'lib/sm.js'
  ]

  function wrapPostMessage(method) {
    return function () {
      postMessage({
          method: method
        , args: Array.prototype.slice.call(arguments, 0)
      })
    }
  }

  var sm
  onmessage = function (msg) {
    var d = msg.data
    switch (d.type) {
      case 'seed':
        root.crypto.randomBytes = function () {
          return d.seed
        }
        if (d.imports) imports = d.imports
        imports.forEach(function (i) {
          importScripts(i)
        })
        break
      case 'init':
        sm = new root.OTR.SM(d.reqs)
        ;['trust','question', 'send', 'abort'].forEach(function (e) {
          sm.on(e, wrapPostMessage(e));
        })
        break
      case 'method':
        sm[d.method].apply(sm, d.args)
        break
    }
  }

}(this))