import OTR from './otr'
import Salsa20 from '../vendor/salsa20'

  function wrapPostMessage(method) {
    return function () {
      postMessage({
          method: method
        , args: Array.prototype.slice.call(arguments, 0)
      })
    }
  }

  var sm
  onmessage = function (e) {
    var data = e.data
    switch (data.type) {
      case 'seed':
        if (typeof crypto !== 'undefined')
          break

        // use salsa20 when there's no prng in webworkers
        var state = new Salsa20(
          data.seed.slice(0, 32),
          data.seed.slice(32)
        )
        var crypto = {};
        crypto.randomBytes = function (n) {
          return state.getBytes(n)
        }
        break
      case 'init':
        sm = new OTR.SM(data.reqs)
        ;['trust','question', 'send', 'abort'].forEach(function (m) {
          sm.on(m, wrapPostMessage(m));
        })
        break
      case 'method':
        sm[data.method].apply(sm, data.args)
        break
    }
  }
