# make test TEST=otr
TEST=*

# make build TASK=otr
TASK=default

all: lint test

lint:
	./node_modules/.bin/jshint -c .jshintrc *.js lib/*.js test/spec/unit/*.js

test:
	./node_modules/.bin/mocha --require reify -G -R spec test/spec/unit/$(TEST).js

build:
	./node_modules/.bin/rollup -c

.PHONY: test build
