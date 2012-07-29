var assert = require('assert')
  , OTR = function () { this.versions = {} }  // just a constructor
  , P = require('../parse.js')

var otr = new OTR()
assert.equal('hi', P.parseMsg(otr, 'hi'), 'Hi.')
assert.equal('hi?OTR', P.parseMsg(otr, 'hi?OTR'), 'OTR!')

var MSGFRAG1 = '?OTR,1,3,?OTR:AAIKAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr,'
var MSGFRAG2 = '?OTR,2,3,JvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiI,'
var MSGFRAG3 = '?OTR,3,3,NLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.,'
var MSGFRAG = '?OTR:AAIKAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOrJvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiINLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.'

assert.equal('', P.parseMsg(otr, MSGFRAG1), 'Message fragment 1.')
assert.equal('', P.parseMsg(otr, MSGFRAG2), 'Message fragment 2.')
var three = P.parseMsg(otr, MSGFRAG3)
assert.equal(three, P.parseMsg(otr, MSGFRAG), 'Message fragment.')
assert.equal('OTR', three, 'Message fragment 3.')

otr = new OTR()
P.parseMsg(otr, '?OTR?')
assert.equal(1, Object.keys(otr.versions).length, 'version 1')
assert.ok(otr.versions['1'], 'version 1')

otr = new OTR()
P.parseMsg(otr, '?OTRv2?')
assert.equal(1, Object.keys(otr.versions).length, 'version 2')
assert.ok(otr.versions['2'], 'version 2')

otr = new OTR()
P.parseMsg(otr, '?OTR?v2?')
assert.equal(2, Object.keys(otr.versions).length, 'version 1 & 2')
assert.ok(otr.versions['1'], 'version 1 & 2')
assert.ok(otr.versions['2'], 'version 1 & 2')

otr = new OTR()
P.parseMsg(otr, '?OTRv24x?')
assert.equal(3, Object.keys(otr.versions).length, 'version 2, 4, x')
assert.ok(otr.versions['2'], 'version 2, 4, x')
assert.ok(otr.versions['4'], 'version 2, 4, x')
assert.ok(otr.versions.x, 'version 2, 4, x')

otr = new OTR()
P.parseMsg(otr, '?OTR?v24x?')
assert.equal(4, Object.keys(otr.versions).length, 'version 1, 2, 4, x')
assert.ok(otr.versions['1'], 'version 1, 2, 4, x')
assert.ok(otr.versions['2'], 'version 1, 2, 4, x')
assert.ok(otr.versions['4'], 'version 1, 2, 4, x')
assert.ok(otr.versions.x, 'version 1, 2, 4, x')

otr = new OTR()
P.parseMsg(otr, '?OTR?v?')
assert.equal(1, Object.keys(otr.versions).length, 'version 1 ?')
assert.ok(otr.versions['1'], 'version 1 ?')

otr = new OTR()
P.parseMsg(otr, '?OTRv?')
assert.equal(0, Object.keys(otr.versions).length, 'version bizarre')

otr = new OTR()
assert.equal('This is an error.', (P.parseMsg(otr, '?OTR Error:This is an error.')).message, 'Err.')