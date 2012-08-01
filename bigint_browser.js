// bigint.js workaround for browser
var BigInt = {}

;(function () {
    var root = this
    ;[ 'str2bigInt'
    , 'bigInt2str'
    , 'multMod'
    , 'powMod'
    , 'inverseMod'
    , 'randBigInt'
    , 'equals'
    , 'sub'
    , 'mod'
    , 'mult'
    , 'divInt_'
    , 'rightShift_'
    , 'leftShift_'
    , 'dup'
    , 'greater'
    , 'add'
    , 'isZero'
    , 'bitSize'
    , 'randTruePrime'
    , 'millerRabin'
    , 'divide_'
    , 'trim'
    , 'expand'
    ].forEach(function (k) { BigInt[k] = root[k] })
}).call(this)