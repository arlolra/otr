var Webworker;

if (typeof Worker !== 'undefined')
  Webworker = Worker
else if (typeof module !== 'undefined' && module.exports)
  Webworker = require('webworker-threads').Worker
else if (typeof window !== 'undefined' && typeof window.Worker !== 'undefined')
  Webworker = window.Worker
else
  throw "No webworker available"

export default Webworker
