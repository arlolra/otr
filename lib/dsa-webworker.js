import DSA from './dsa'

  function sendMsg(type, val) {
    postMessage({ type: type, val: val })
  }

  onmessage = function (e) {
    var data = e.data;

    if (data.debug) sendMsg('debug', 'DSA key creation started')
    var dsa
    try {
      dsa = new DSA()
    } catch (e) {
      if (data.debug) sendMsg('debug', e.toString())
      return
    }
    if (data.debug) sendMsg('debug', 'DSA key creation finished')

    sendMsg('data', dsa.packPrivate())
  }
