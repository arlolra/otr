/*global describe it */
var assert = require('assert')
  , BigInt = require('../../../vendor/bigint.js')

describe('BigInt', function() {
  "use strict";

  it('should test lbit', function () {
    assert.equal(BigInt.lbit(4), 2)
    assert.equal(BigInt.lbit(5), 0)
  })

  it('should test lowestSetBit', function () {
    var four = BigInt.int2bigInt(4, 3)
    var f = BigInt.str2bigInt(Math.pow(2, 15).toString(2), 2)
    assert.equal(BigInt.lowestSetBit(four), 2)
    assert.equal(BigInt.lowestSetBit(f), 15)
  })

  it('should test jacobi', function () {
    var n = BigInt.str2bigInt("3439601197", 10)
    var a = BigInt.int2bigInt(5, 3)
    assert.equal(BigInt.jacobi(a, n), -1)
    n = BigInt.str2bigInt("1236", 10)
    a = BigInt.str2bigInt("20003", 10)
    assert.equal(BigInt.jacobi(a, n), 1)
    n = BigInt.str2bigInt("1001", 10)
    a = BigInt.str2bigInt("9907", 10)
    assert.equal(BigInt.jacobi(a, n), -1)
    n = BigInt.str2bigInt("101", 10)
    a = BigInt.str2bigInt("27", 10)
    assert.equal(BigInt.jacobi(a, n), -1)
    n = BigInt.str2bigInt("45", 10)
    a = BigInt.str2bigInt("19", 10)
    assert.equal(BigInt.jacobi(a, n), 1)
    n = BigInt.str2bigInt("21", 10)
    a = BigInt.str2bigInt("8", 10)
    assert.equal(BigInt.jacobi(a, n), -1)
    n = BigInt.str2bigInt("21", 10)
    a = BigInt.str2bigInt("5", 10)
    assert.equal(BigInt.jacobi(a, n), 1)
    n = BigInt.str2bigInt("17", 10)
    a = BigInt.str2bigInt("5", 10)
    assert.equal(BigInt.jacobi(a, n), -1)
    n = BigInt.str2bigInt("17", 10)
    a = BigInt.str2bigInt("13", 10)
    assert.equal(BigInt.jacobi(a, n), 1)
  })

  it('should test twoToThe', function () {
    assert.equal(BigInt.bigInt2str(BigInt.twoToThe(20), 10), "1048576")
    assert.equal(BigInt.bigInt2str(BigInt.twoToThe(30), 10), "1073741824")
    assert.equal(BigInt.bigInt2str(BigInt.twoToThe(32), 10), "4294967296")
    assert.equal(BigInt.bigInt2str(BigInt.twoToThe(63), 10), "9223372036854775808")
  })

  it('should test perfectSquare', function () {
    assert.ok(BigInt.perfectSquare(BigInt.str2bigInt("100", 10)))
    assert.ok(BigInt.perfectSquare(BigInt.str2bigInt("998001", 10)))
    assert.ok(BigInt.perfectSquare(BigInt.str2bigInt("999998000001", 10)))
    assert.ok(!BigInt.perfectSquare(BigInt.str2bigInt("99999400007", 10)))
    assert.ok(BigInt.perfectSquare(BigInt.str2bigInt("777777777777777744351960257494201", 10)))
    // test special case
    assert.ok(!BigInt.perfectSquare(BigInt.str2bigInt("99", 10)))
    assert.ok(!BigInt.perfectSquare(BigInt.str2bigInt("998000", 10)))
  })
  
  it('should test lucas', function () {

    // assert.ok(!BigInt.lucas(BigInt.str2bigInt("8", 10)))
    // assert.ok(BigInt.lucas(BigInt.str2bigInt("11", 10)))
    // assert.ok(BigInt.lucas(BigInt.str2bigInt("17", 10)))
    // assert.ok(BigInt.lucas(BigInt.str2bigInt("2003", 10)))
    // assert.ok(BigInt.lucas(BigInt.str2bigInt("3571", 10)))
    // assert.ok(BigInt.lucas(BigInt.str2bigInt("18014398241046527", 10)))
    // assert.ok(BigInt.lucas(BigInt.str2bigInt("3439601197", 10)))
    
    // var i = 0, j = 0
    // for (; j < 100; i++) {
    //   if (BigInt.lucas(BigInt.str2bigInt(i.toString(), 10))) {
    //     console.log(i)
    //     j += 1
    //   }
    // }
    

  })

})