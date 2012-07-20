#!/usr/bin/env bash

SOURCE="${BASH_SOURCE[0]}"
DIR="$(dirname "$SOURCE")"

for file in $(find $DIR/*.test.js)
do
  node $file
done
