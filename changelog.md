
0.2.7 / 2013-10-12
==================

 * canonical amd support

0.2.6 / 2013-09-12
==================

 * client should handle trust state
 * smp should go both ways

0.2.5 / 2013-08-20
==================

 * add encrypted parameter to ui listener
 * fix whitespace start ake always starting ake

0.2.4 / 2013-08-19
==================

 * some constant-time compares

0.2.3 / 2013-08-17
==================

 * bits in base
 * fix smp in ww #35
 * avoid possibility of floats

0.2.2 / 2013-08-10
==================

 * fix smp exponent bits

0.2.1 / 2013-07-06
==================

 * use less random bytes
 * fix horrible merge

0.2.0 / 2013-07-04
==================

 * smp in webworker
 * missing bits in randBigInt_
 * don't waste entropy
 * fix for instance tags greater than max uint
 * some linting
 * fix amd
 * always run the libotr test

0.1.8 / 2013-06-18
==================

 * try to avoid key compromise from entropy failures
 * upgrade dependencies
 * remove dead code

0.1.7 / 2013-06-14
==================

 * just some cleanup

0.1.6 / 2013-06-12
==================

 * AMD support
 * upgrade grunt

0.1.5 / 2013-05-23
==================

 * fix utf8 filenames
 * some checks and guards in otr
 * option to remove DSA parameter caching
 * nulled out some values in the AKE
 * don't repeat bases in Miller Rabin
 * update bigint.js to v5.5

0.1.4 / 2013-03-20
==================

  * api for extra symmetric key
  * switch to salsa20
  * only send_interval on fragments

0.1.3 / 2013-03-10
==================

  * remove ui trigger when buddy closes private connection

0.1.2 / 2013-03-08
==================

  * fix importing keys

0.1.1 / 2013-03-08
==================

  * test against libotr
  * import long-lived keys from adium / pidgin

0.1.0 / 2013-03-02
==================

  * trigger statuses
  * use strict
  * inherit from eventemitter

0.0.13 / 2013-01-12
===================

  * use golang simplifications to generate dsa params

0.0.12 / 2013-01-06
===================

  * fix plaintext msgs
  * receive type 1 tlvs
  * import / export private keys
  * notify smp aborted
  * more tests

0.0.11 / 2012-11-15
===================

  * socialist millionaire api

0.0.10 / 2012-11-12
===================

  * smp group check
  * better error handling

0.0.9 / 2012-10-25
==================

  * switch to MPL v2.0

0.0.8 / 2012-09-24
==================

  * dsa key generation fixes

0.0.7 / 2012-09-20
==================

  * support utf8 encoded messages

0.0.6 / 2012-09-17
==================

  * support v3 of the otr protocol
  * change and document fingerprint api
  * fix read int

0.0.5 / 2012-08-25
==================

  * pad signature
  * namespace
  * whitespace tags
  * replace Math.random
  * document ake
  * don't allow v1

0.0.4 / 2012-08-21
==================

  * fix send message fragments
  * bugs in ake state machine

0.0.3 / 2012-08-19
==================

  * build step
  * document options
  * send message fragments
  * send interval
  * more ake tests
  * separating states into module

0.0.2 / 2012-08-11
==================

  * not just a wip
  * ake adium
  * properly parse Latin1 strings

0.0.1 / 2012-08-05
==================

  * first somewhat working version
