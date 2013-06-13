
  return CryptoJS

}

  var root = this

  if (typeof define === "function" && define.amd) {
    define(CryptoJS)
  } else if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoJS()
  } else {
    root.CryptoJS = CryptoJS()
  }

}).call(this)