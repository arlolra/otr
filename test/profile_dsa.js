#!/usr/bin/env node
"use strict";

var fs = require('fs'),
    path = require('path'),
    DSA = require('../lib/dsa.js');

var ws = fs.createWriteStream(path.join(__dirname, './data.csv'))

function main() {
  var i, start, key, end, times = [], count = 1000;
  for (i = 0; i < count; i++) {
    start = (new Date()).getTime()
    key = new DSA(null, { bit_length: 1024, nocache: true });
    end = (new Date()).getTime() - start;
    times.push(end);
    console.log((i + 1) + ') ' + end + 'ms');
    ws.write(end + '\n');
  }

  var avg = times.reduce(function (prev, next) {
    return prev + next;
  }, 0) / count / 1000;

  console.log('\naverage seconds per key: ' + avg + '\n');
  ws.end();
}

ws.on('open', main);
ws.on('close', function () { process.exit(0); })
