/* eslint-env node, mocha */
'use strict';

var assert = require('assert');
var elliptic = require('../');
var utils = elliptic.utils;
var toArray = elliptic.utils.toArray;
var eddsa = elliptic.eddsa;

function toHex(arr) {
  return elliptic.utils.toHex(arr).toUpperCase();
}

var MAX_PROGRAMMATIC = process.env.CI ? Infinity : 50;

describe('ed25519 derivations', function() {
  var expectedTests = 256;
  var ed25519;
  var derivations;

  before(function() {
    ed25519 = new eddsa('ed25519');
    derivations = require('./fixtures/derivation-fixtures');
    assert.equal(derivations.length, expectedTests);
  });

  function testFactory(i) {
    it('can compute correct a and A for secret: ' + i, function() {
      var test = derivations[i];
      var secret = utils.toArray(test.secret_hex, 'hex');
      var key = ed25519.keyFromSecret(secret);
      assert.equal(toHex(key.privBytes()), test.a_hex);
      var xRecovered = toHex(ed25519.encodeInt(
        ed25519.decodePoint(key.pubBytes()).getX()));
      assert.equal(xRecovered, test.A_P.x);
      assert.equal(toHex(key.pubBytes()), test.A_hex);
    });
  }

  for (var i = 0; i < Math.min(expectedTests, MAX_PROGRAMMATIC); i++)
    testFactory(i);
});

describe('sign.input ed25519 test vectors', function() {
  var expectedTests = 1024;
  var ed25519;
  var lines;

  before(function(done) {
    ed25519 = new eddsa('ed25519');
    require('fs').readFile(__dirname + '/fixtures/sign.input', function(err, f) {
      lines = f.toString().split('\n');
      assert.equal(lines.length, expectedTests + 1 /*blank line*/);
      done();
    });
  });

  function testFactory(i) {
    it('vector ' + i, function() {
      var split = lines[i].toUpperCase().split(':');
      var key = ed25519.keyFromSecret(split[0].slice(0, 64));
      var expectedPk = split[0].slice(64);

      assert.equal(toHex(key.pubBytes()), expectedPk);

      var msg = toArray(split[2], 'hex');
      var sig = key.sign(msg).toHex();
      var sigR = sig.slice(0, 64);
      var sigS = sig.slice(64);

      assert.equal(sigR, split[3].slice(0, 64));
      assert.equal(sigS, split[3].slice(64, 128));
      assert(key.verify(msg, sig));

      var forged = msg.length === 0 ? [ 0x78 ] /*ord('x')*/:
        msg.slice(0, msg.length - 1).concat(
          (msg[(msg.length - 1)] + 1) % 256);

      assert.equal(msg.length || 1, forged.length);
      assert(!key.verify(forged, sig));
    });
  }
  for (var i = 0; i < Math.min(expectedTests, MAX_PROGRAMMATIC); i++)
    testFactory(i);
});

describe('EDDSA(\'ed25519\')', function() {
  var ed25519;

  before(function() {
    ed25519 = new eddsa('ed25519');
  });

  it('has encodingLength of 32', function() {
    assert.equal(32, ed25519.encodingLength);
  });

  it('can sign/verify messages', function() {
    var secret = toArray(new Array(65).join('0'), 'hex');
    assert(secret.length === 32);
    var msg = [ 0xB, 0xE, 0xE, 0xF ];
    var key = ed25519.keyFromSecret(secret);
    var sig = key.sign(msg).toHex();

    var R = '8F1B9A7FDB22BCD2C15D4695B1CE2B063CBFAEC9B00BE360427BAC9533943F6C';
    var S = '5F0B380FD7F2E43B70AB2FA29F6C6E3FFC1012710E174786814012324BF19B0C';

    assert.equal(sig.slice(0, 64), R);
    assert.equal(sig.slice(64), S);

    assert(key.verify(msg, sig));
  });

  describe('signature length', function() {
    var secret = toArray(new Array(65).join('0'), 'hex');

    // A malformed signature must either throw or fail to verify
    function rejects(fn) {
      try {
        return fn() === false;
      } catch (e) {
        return true;
      }
    }

    it('rejects signatures with trailing bytes', function() {
      var msg = [ 0xB, 0xE, 0xE, 0xF ];
      var key = ed25519.keyFromSecret(secret);
      var sig = key.sign(msg).toHex();
      assert(key.verify(msg, sig));

      assert(rejects(function() {
        return key.verify(msg, sig + '00');
      }), 'hex signature with trailing zero byte must not verify');

      assert(rejects(function() {
        return key.verify(msg, sig + '0000');
      }), 'hex signature with trailing zero bytes must not verify');

      var bytes = toArray(sig, 'hex').concat([ 0 ]);
      assert(rejects(function() {
        return key.verify(msg, bytes);
      }), 'byte signature with trailing zero byte must not verify');

      assert(rejects(function() {
        return ed25519.verify(msg, sig + '00', key.getPublic());
      }), 'EDDSA#verify must reject signature with trailing zero byte');
    });

    it('rejects truncated signatures', function() {
      var key = ed25519.keyFromSecret(secret);
      var msg;
      var sig;
      // Find a signature whose most significant S byte is zero, so that
      // dropping it does not change the decoded S value
      for (var i = 0; i < 256; i++) {
        msg = [ i ];
        sig = key.sign(msg).toHex();
        if (sig.slice(-2) === '00')
          break;
      }
      assert.equal(sig.slice(-2), '00');
      assert(key.verify(msg, sig));

      var truncated = sig.slice(0, -2);
      assert(rejects(function() {
        return key.verify(msg, truncated);
      }), 'truncated signature must not verify');

      assert(rejects(function() {
        return key.verify(msg, toArray(truncated, 'hex'));
      }), 'truncated byte signature must not verify');
    });
  });

  describe('KeyPair', function() {
    var pair;
    var secret = '00000000000000000000000000000000' +
                 '00000000000000000000000000000000';

    before(function() {
      pair = ed25519.keyFromSecret(secret);
    });

    it('can be created with keyFromSecret/keyFromPublic', function() {
      var pubKey = ed25519.keyFromPublic(toHex(pair.pubBytes()));
      assert(pubKey.pub() instanceof ed25519.pointClass);
      assert(pubKey.pub().eq(pair.pub()));
    });
    it('#getSecret returns bytes with optional encoding', function() {
      assert(Array.isArray(pair.getSecret()));
      assert(pair.getSecret('hex') === secret);
    });
    it('#getPub returns bytes with optional encoding', function() {
      assert(Array.isArray(pair.getPublic()));
      assert.equal(pair.getPublic('hex'),
        '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29');
    });
  });
});
