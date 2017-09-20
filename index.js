import DSA from './lib/dsa'
import OTR from './lib/otr'

if (window) {
  window.DSA = DSA
  window.OTR = OTR
}

export {DSA, OTR}
