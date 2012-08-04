# make test TEST=otr
TEST=*

test:
	./node_modules/.bin/mocha -R spec test/spec/unit/$(TEST).js

.PHONY: test