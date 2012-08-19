# make test TEST=otr
TEST=*

test:
	./node_modules/.bin/mocha -R spec test/spec/unit/$(TEST).js

build:
	./node_modules/.bin/grunt

.PHONY: test build