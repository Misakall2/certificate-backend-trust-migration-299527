/**
 * Tests for the selectable certificate signature verification backends
 * (lib/x509-verify-backend.js) and their integration with
 * pki.verifyCertificateChain().
 *
 * RSA chains are generated locally at test time; EC and RSASSA-PSS
 * certificates (which forge cannot generate itself) come from the fixed
 * fixtures in x509-verify-backend-fixtures.js. No certificates are
 * downloaded and no real service is contacted. Private keys generated
 * here never leave the test process and are never printed.
 */
var ASSERT = require('assert');
var FORGE = require('../../lib/forge');
var MD = require('../../lib/md.all');
var PKI = require('../../lib/pki');
var FIXTURES = require('./x509-verify-backend-fixtures');

(function() {
  var BACKENDS = PKI.certificateVerificationBackends;
  var VERR = PKI.certificateVerificationError;
  var CERR = PKI.certificateError;
  var nodeAvailable = BACKENDS.node.isAvailable();
  // runs a test only when the Node.js built-in crypto backend is
  // available in this runtime (it is not in browsers)
  var itNode = nodeAvailable ? it : it.skip;

  var VALID_FROM = new Date('2020-01-01T00:00:00Z');
  var VALID_TO = new Date('2030-01-01T00:00:00Z');
  var CHECK_DATE = new Date('2025-06-01T00:00:00Z');
  var FIXTURE_DATE = new Date('2027-06-01T00:00:00Z');

  function _attrs(cn) {
    return [{name: 'commonName', value: cn}];
  }

  function _makeCert(options) {
    var cert = PKI.createCertificate();
    cert.publicKey = options.publicKey;
    cert.serialNumber = options.serialNumber;
    cert.validity.notBefore = options.notBefore || VALID_FROM;
    cert.validity.notAfter = options.notAfter || VALID_TO;
    cert.setSubject(_attrs(options.subject));
    cert.setIssuer(options.issuer);
    cert.setExtensions(options.extensions || []);
    cert.sign(options.signingKey, options.md || MD.sha256.create());
    return cert;
  }

  var _caExtensions = [
    {name: 'basicConstraints', cA: true, critical: true},
    {name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true}
  ];
  var _leafExtensions = [
    {name: 'basicConstraints', cA: false, critical: true},
    {name: 'keyUsage', digitalSignature: true, critical: true}
  ];

  // the locally generated short chain and its variants; built once
  var chain = {};

  function _buildChain() {
    var serial = 0;
    function _serial() {
      ++serial;
      return ('0' + serial.toString(16)).slice(-2);
    }
    function _ca(name, issuerAttrs, signingKey, extraExtensions) {
      var keys = PKI.rsa.generateKeyPair(1024);
      // extra extensions replace defaults with the same name
      var extensions = _caExtensions.slice();
      (extraExtensions || []).forEach(function(ext) {
        for(var i = 0; i < extensions.length; ++i) {
          if(extensions[i].name === ext.name) {
            extensions.splice(i, 1);
            break;
          }
        }
        extensions.push(ext);
      });
      var cert = _makeCert({
        subject: name,
        issuer: issuerAttrs || _attrs(name),
        publicKey: keys.publicKey,
        signingKey: signingKey || keys.privateKey,
        serialNumber: _serial(),
        extensions: extensions
      });
      return {keys: keys, cert: cert};
    }
    function _leaf(name, issuer, signingKey, options) {
      options = options || {};
      var keys = options.keys || PKI.rsa.generateKeyPair(1024);
      var cert = _makeCert({
        subject: name,
        issuer: issuer.subject.attributes,
        publicKey: keys.publicKey,
        signingKey: signingKey,
        serialNumber: _serial(),
        extensions: _leafExtensions,
        notBefore: options.notBefore,
        notAfter: options.notAfter,
        md: options.md
      });
      return {keys: keys, cert: cert};
    }

    // root -> intermediate -> leaf
    chain.root = _ca('Test Root');
    chain.intermediate = _ca(
      'Test Intermediate', chain.root.cert.subject.attributes,
      chain.root.keys.privateKey);
    chain.leaf = _leaf(
      'Test Leaf', chain.intermediate.cert,
      chain.intermediate.keys.privateKey);

    // leaf whose issuer name matches the intermediate but that was
    // signed with the wrong (root) key
    chain.badLeaf = _leaf(
      'Test Bad Leaf', chain.intermediate.cert, chain.root.keys.privateKey,
      {keys: chain.leaf.keys});

    // leaf that is expired at CHECK_DATE
    chain.expiredLeaf = _leaf(
      'Test Expired Leaf', chain.intermediate.cert,
      chain.intermediate.keys.privateKey, {
        keys: chain.leaf.keys,
        notBefore: new Date('2020-01-01T00:00:00Z'),
        notAfter: new Date('2021-01-01T00:00:00Z')
      });

    // leaves using weak signature algorithms (rejected by the fixed
    // allowlist of the node backend, verifiable by the forge backend)
    chain.sha1Leaf = _leaf(
      'Test SHA1 Leaf', chain.intermediate.cert,
      chain.intermediate.keys.privateKey,
      {keys: chain.leaf.keys, md: MD.sha1.create()});
    chain.md5Leaf = _leaf(
      'Test MD5 Leaf', chain.intermediate.cert,
      chain.intermediate.keys.privateKey,
      {keys: chain.leaf.keys, md: MD.md5.create()});

    // rootPl -> intA (pathLenConstraint: 0) -> intB -> leafPl
    chain.rootPl = _ca('Test PathLen Root');
    chain.intA = _ca(
      'Test PathLen Int A', chain.rootPl.cert.subject.attributes,
      chain.rootPl.keys.privateKey,
      [{name: 'basicConstraints', cA: true, pathLenConstraint: 0,
        critical: true}]);
    chain.intB = _ca(
      'Test PathLen Int B', chain.intA.cert.subject.attributes,
      chain.intA.keys.privateKey);
    chain.leafPl = _leaf(
      'Test PathLen Leaf', chain.intB.cert, chain.intB.keys.privateKey,
      {keys: chain.leaf.keys});

    // intermediate without the keyCertSign key usage
    chain.intNoSign = _ca(
      'Test NoSign Int', chain.root.cert.subject.attributes,
      chain.root.keys.privateKey,
      [{name: 'keyUsage', digitalSignature: true, critical: true}]);
    chain.leafNoSign = _leaf(
      'Test NoSign Leaf', chain.intNoSign.cert,
      chain.intNoSign.keys.privateKey, {keys: chain.leaf.keys});

    // two self-signed roots with the same subject name but different
    // keys (cross-signing candidates); sharedLeaf is signed by rootB
    chain.rootA = _ca('Test Shared Root');
    chain.rootB = _ca('Test Shared Root');
    chain.sharedLeaf = _leaf(
      'Test Shared Leaf', chain.rootB.cert, chain.rootB.keys.privateKey,
      {keys: chain.leaf.keys});

    // a self-signed certificate that is its own trust anchor candidate
    chain.selfSigned = _ca('Test Self Signed');
  }

  /**
   * Runs pki.verifyCertificateChain(), capturing the per-depth
   * verification results instead of throwing on the first policy
   * failure. Typed backend errors still propagate and are returned as
   * 'thrown'.
   */
  function _runChain(caStore, certs, options) {
    var seen = [];
    options = options || {};
    options.verify = function(vfd, depth) {
      seen.push({vfd: vfd, depth: depth});
      // consume policy errors so every depth is reported
      return true;
    };
    try {
      return {result: PKI.verifyCertificateChain(caStore, certs, options),
        seen: seen};
    } catch(e) {
      return {thrown: e, seen: seen};
    }
  }

  function _store() {
    var certs = Array.prototype.slice.call(arguments);
    return PKI.createCaStore(certs.map(function(entry) {
      return entry.cert;
    }));
  }

  describe('x509 certificate verification backends', function() {
    before(function() {
      _buildChain();
    });

    describe('backend registry', function() {
      it('should expose the forge and node backends', function() {
        ASSERT.equal(typeof BACKENDS.forge, 'object');
        ASSERT.equal(typeof BACKENDS.node, 'object');
        ASSERT.equal(BACKENDS.forge.name, 'forge');
        ASSERT.equal(BACKENDS.node.name, 'node');
        ASSERT.equal(BACKENDS.forge.isAvailable(), true);
      });

      it('should default to the forge backend', function() {
        var backend = PKI.getCertificateVerificationBackend();
        ASSERT.equal(backend.name, 'forge');
        ASSERT.equal(
          PKI.getCertificateVerificationBackend('node').name, 'node');
      });

      it('should reject unknown backend names and invalid objects',
        function() {
          ASSERT.throws(function() {
            PKI.getCertificateVerificationBackend('does-not-exist');
          }, /Unknown certificate verification backend/);
          ASSERT.throws(function() {
            PKI.getCertificateVerificationBackend(42);
          }, /Invalid certificate verification backend/);
        });

      it('should report node backend availability for this runtime',
        function() {
          // in Node.js >= 15.6 the backend is available; in browsers
          // (karma) it is not -- either way it must be a boolean
          ASSERT.equal(typeof nodeAvailable, 'boolean');
        });
    });

    describe('signature verification', function() {
      it('should verify a valid signature with both backends', function() {
        ASSERT.equal(PKI.verifyCertificateSignature(
          chain.intermediate.cert, chain.leaf.cert), true);
        ASSERT.equal(PKI.verifyCertificateSignature(
          chain.intermediate.cert, chain.leaf.cert,
          {backend: 'forge'}), true);
      });

      itNode('should verify a valid signature with the node backend',
        function() {
          ASSERT.equal(PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.leaf.cert,
            {backend: 'node'}), true);
        });

      itNode('should return false for a wrong signature, not throw',
        function() {
          // badLeaf names the intermediate as issuer but was signed
          // with the root key
          ASSERT.equal(PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.badLeaf.cert,
            {backend: 'node'}), false);
          ASSERT.equal(PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.badLeaf.cert,
            {backend: 'forge'}), false);
        });

      itNode('should distinguish parse failure, unsupported algorithm, ' +
        'and signature mismatch', function() {
        // parse failure
        ASSERT.throws(function() {
          PKI.verifyCertificateSignature(
            chain.root.cert, 'this is not a certificate',
            {backend: 'node'});
        }, function(e) {
          return e.code === VERR.certificate_parse_failed &&
              e.stage === 'parse';
        });
        // unsupported algorithm (SHA-1 is not in the allowlist)
        ASSERT.throws(function() {
          PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.sha1Leaf.cert,
            {backend: 'node'});
        }, function(e) {
          return e.code === VERR.unsupported_signature_algorithm &&
              !!e.signatureOid;
        });
        // signature mismatch is a result, not an exception
        ASSERT.equal(PKI.verifyCertificateSignature(
          chain.intermediate.cert, chain.badLeaf.cert,
          {backend: 'node'}), false);
      });
    });

    describe('chain verification policy (shared by both backends)',
      function() {
        // each case runs on the forge backend (the browser-compatible
        // path) and, when available, on the node backend, and must
        // reach a comparable conclusion
        var backendNames = nodeAvailable ? ['forge', 'node'] : ['forge'];

        function _forEachBackend(fn) {
          backendNames.forEach(function(name) {
            fn(name, {verificationBackend: name,
              validityCheckDate: CHECK_DATE});
          });
        }

        it('should verify a valid short chain on all backends', function() {
          _forEachBackend(function(name, options) {
            var run = _runChain(
              _store(chain.root),
              [chain.leaf.cert, chain.intermediate.cert], options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(run.result, true, 'backend: ' + name);
            ASSERT.deepEqual(run.seen.map(function(s) {
              return s.vfd;
            }), [true, true]);
          });
        });

        it('should reject an expired certificate on all backends',
          function() {
            _forEachBackend(function(name, options) {
              var run = _runChain(
                _store(chain.root),
                [chain.expiredLeaf.cert, chain.intermediate.cert],
                options);
              ASSERT.ifError(run.thrown);
              ASSERT.equal(
                run.seen[0].vfd, CERR.certificate_expired,
                'backend: ' + name);
            });
          });

        it('should accept the same certificate within its validity ' +
          'period when the verification time is injected', function() {
          _forEachBackend(function(name, options) {
            options.validityCheckDate = new Date('2020-06-01T00:00:00Z');
            var run = _runChain(
              _store(chain.root),
              [chain.expiredLeaf.cert, chain.intermediate.cert],
              options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(run.result, true, 'backend: ' + name);
          });
        });

        it('should reject a wrong signature on all backends', function() {
          _forEachBackend(function(name, options) {
            var run = _runChain(
              _store(chain.root),
              [chain.badLeaf.cert, chain.intermediate.cert], options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(
              run.seen[0].vfd, CERR.bad_certificate, 'backend: ' + name);
          });
        });

        it('should not establish trust from a self-signed certificate ' +
          'absent from the CA store', function() {
          _forEachBackend(function(name, options) {
            var run = _runChain(
              PKI.createCaStore(), [chain.selfSigned.cert], options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(
              run.seen[0].vfd, CERR.unknown_ca, 'backend: ' + name);
          });
        });

        it('should not establish trust from a root name appearing in ' +
          'the chain', function() {
          _forEachBackend(function(name, options) {
            // the full chain including the self-signed root, but the
            // CA store is empty: the root in the chain is not a
            // caller-provided trust anchor
            var run = _runChain(
              PKI.createCaStore(),
              [chain.leaf.cert, chain.intermediate.cert,
                chain.root.cert],
              options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(
              run.seen[2].vfd, CERR.unknown_ca, 'backend: ' + name);
          });
        });

        it('should reject an untrusted root on all backends', function() {
          _forEachBackend(function(name, options) {
            // store trusts an unrelated root, not ours
            var run = _runChain(
              _store(chain.rootA),
              [chain.leaf.cert, chain.intermediate.cert], options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(
              run.seen[1].vfd, CERR.unknown_ca, 'backend: ' + name);
          });
        });

        it('should enforce the intermediate pathLenConstraint on all ' +
          'backends', function() {
          _forEachBackend(function(name, options) {
            var run = _runChain(
              _store(chain.rootPl),
              [chain.leafPl.cert, chain.intB.cert, chain.intA.cert],
              options);
            ASSERT.ifError(run.thrown);
            // intA (depth 2) violates pathLenConstraint: 0
            ASSERT.equal(
              run.seen[2].vfd, CERR.bad_certificate, 'backend: ' + name);
          });
        });

        it('should reject an intermediate without keyCertSign on all ' +
          'backends', function() {
          _forEachBackend(function(name, options) {
            var run = _runChain(
              _store(chain.root),
              [chain.leafNoSign.cert, chain.intNoSign.cert], options);
            ASSERT.ifError(run.thrown);
            ASSERT.equal(
              run.seen[1].vfd, CERR.bad_certificate, 'backend: ' + name);
          });
        });
      });

    describe('cross-signed issuer candidates', function() {
      it('should try same-name candidates in store order on all ' +
        'backends', function() {
        var names = nodeAvailable ? ['forge', 'node'] : ['forge'];
        names.forEach(function(name) {
          // rootA (wrong key) is inserted before rootB (right key)
          var store = PKI.createCaStore(
            [chain.rootA.cert, chain.rootB.cert]);
          var run = _runChain(store, [chain.sharedLeaf.cert], {
            verificationBackend: name,
            validityCheckDate: CHECK_DATE
          });
          ASSERT.ifError(run.thrown);
          ASSERT.equal(run.result, true, 'backend: ' + name);
        });
      });

      it('should honor a deterministic candidate bound', function() {
        var store = PKI.createCaStore(
          [chain.rootA.cert, chain.rootB.cert]);
        // only the first (wrong-key) candidate is tried
        var run = _runChain(store, [chain.sharedLeaf.cert], {
          validityCheckDate: CHECK_DATE,
          maxIssuerCandidates: 1
        });
        ASSERT.ifError(run.thrown);
        ASSERT.equal(run.seen[0].vfd, CERR.bad_certificate);
      });

      it('should not treat same-name certificates as the same key',
        function() {
          ASSERT.equal(
            chain.rootA.cert.subject.attributes[0].value,
            chain.rootB.cert.subject.attributes[0].value);
          // a leaf signed by rootB must not verify against rootA
          ASSERT.equal(PKI.verifyCertificateSignature(
            chain.rootA.cert, chain.sharedLeaf.cert), false);
          ASSERT.equal(PKI.verifyCertificateSignature(
            chain.rootB.cert, chain.sharedLeaf.cert), true);
        });
    });

    describe('algorithm allowlist (node backend)', function() {
      itNode('should reject SHA-1 signatures that the forge backend ' +
        'accepts', function() {
        // documented difference: the forge backend verifies SHA-1,
        // the node backend rejects it by policy
        ASSERT.equal(PKI.verifyCertificateSignature(
          chain.intermediate.cert, chain.sha1Leaf.cert,
          {backend: 'forge'}), true);
        ASSERT.throws(function() {
          PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.sha1Leaf.cert,
            {backend: 'node'});
        }, function(e) {
          return e.code === VERR.unsupported_signature_algorithm;
        });
      });

      itNode('should reject MD5 signatures', function() {
        ASSERT.throws(function() {
          PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.md5Leaf.cert,
            {backend: 'node'});
        }, function(e) {
          return e.code === VERR.unsupported_signature_algorithm;
        });
      });

      itNode('should report the allowlist rejection through chain ' +
        'verification instead of swallowing it', function() {
        var run = _runChain(
          _store(chain.root),
          [chain.sha1Leaf.cert, chain.intermediate.cert], {
            verificationBackend: 'node',
            validityCheckDate: CHECK_DATE
          });
        ASSERT.ok(run.thrown, 'expected a typed error to be thrown');
        ASSERT.equal(
          run.thrown.code, VERR.unsupported_signature_algorithm);
      });
    });

    describe('no implicit fallback', function() {
      itNode('should not consult the forge backend when the node ' +
        'backend is selected', function() {
        var calls = 0;
        var original = BACKENDS.forge.verifySignature;
        BACKENDS.forge.verifySignature = function() {
          ++calls;
          return original.apply(this, arguments);
        };
        try {
          // failing case: SHA-1 leaf is rejected by the node
          // backend; the failure must not be retried with forge
          ASSERT.throws(function() {
            PKI.verifyCertificateChain(
              _store(chain.root),
              [chain.sha1Leaf.cert, chain.intermediate.cert], {
                verificationBackend: 'node',
                validityCheckDate: CHECK_DATE
              });
          }, function(e) {
            return e.code === VERR.unsupported_signature_algorithm;
          });
          // succeeding case, for good measure
          ASSERT.equal(PKI.verifyCertificateChain(
            _store(chain.root),
            [chain.leaf.cert, chain.intermediate.cert], {
              verificationBackend: 'node',
              validityCheckDate: CHECK_DATE
            }), true);
          ASSERT.equal(calls, 0,
            'forge backend was consulted despite node selection');
        } finally {
          BACKENDS.forge.verifySignature = original;
        }
      });

      it('should not consult the node backend when the forge backend ' +
        'is selected', function() {
        var calls = 0;
        var original = BACKENDS.node.verifySignature;
        BACKENDS.node.verifySignature = function() {
          ++calls;
          return original.apply(this, arguments);
        };
        try {
          ASSERT.equal(PKI.verifyCertificateChain(
            _store(chain.root),
            [chain.leaf.cert, chain.intermediate.cert], {
              verificationBackend: 'forge',
              validityCheckDate: CHECK_DATE
            }), true);
          ASSERT.equal(calls, 0,
            'node backend was consulted despite forge selection');
        } finally {
          BACKENDS.node.verifySignature = original;
        }
      });
    });

    describe('backend availability', function() {
      it('should throw a recognizable error when the selected backend ' +
        'is unavailable', function() {
        var unavailable = {
          name: 'node',
          isAvailable: function() {
            return false;
          },
          verifySignature: function() {
            throw new Error('must not be called');
          }
        };
        ASSERT.throws(function() {
          PKI.verifyCertificateChain(
            _store(chain.root),
            [chain.leaf.cert, chain.intermediate.cert], {
              verificationBackend: unavailable,
              validityCheckDate: CHECK_DATE
            });
        }, function(e) {
          return e.code === VERR.backend_unavailable &&
              e.stage === 'backend';
        });
        ASSERT.throws(function() {
          PKI.verifyCertificateSignature(
            chain.root.cert, chain.leaf.cert, {backend: unavailable});
        }, function(e) {
          return e.code === VERR.backend_unavailable;
        });
      });
    });

    describe('ECDSA fixtures (node backend)', function() {
      itNode('should verify an ECDSA (P-256) signature', function() {
        ASSERT.equal(PKI.verifyCertificateSignature(
          FIXTURES.ecRootPem, FIXTURES.ecLeafPem,
          {backend: 'node'}), true);
      });

      itNode('should accept DER-encoded input', function() {
        var der = FORGE.pem.decode(FIXTURES.ecLeafPem)[0].body;
        ASSERT.equal(PKI.verifyCertificateSignature(
          FIXTURES.ecRootPem, der, {backend: 'node'}), true);
      });

      itNode('should return false for an ECDSA signature with the ' +
        'wrong issuer key', function() {
        ASSERT.equal(PKI.verifyCertificateSignature(
          FIXTURES.ecOtherPem, FIXTURES.ecLeafPem,
          {backend: 'node'}), false);
      });

      it('should report ECDSA as unsupported on the forge backend',
        function() {
          ASSERT.throws(function() {
            PKI.verifyCertificateSignature(
              FIXTURES.ecRootPem, FIXTURES.ecLeafPem,
              {backend: 'forge'});
          }, function(e) {
            return e.code === VERR.unsupported_key_algorithm &&
              !!e.keyOid;
          });
        });
    });

    describe('RSASSA-PSS fixtures', function() {
      itNode('should verify PSS signatures with conforming parameters ' +
        'on both backends', function() {
        ASSERT.equal(PKI.verifyCertificateSignature(
          FIXTURES.pssRootPem, FIXTURES.pssLeafPem,
          {backend: 'node'}), true);
        ASSERT.equal(PKI.verifyCertificateSignature(
          FIXTURES.pssRootPem, FIXTURES.pssLeafPem,
          {backend: 'forge'}), true);
      });

      itNode('should verify a PSS chain on both backends', function() {
        var root = PKI.certificateFromPem(FIXTURES.pssRootPem);
        var leaf = PKI.certificateFromPem(FIXTURES.pssLeafPem);
        var store = PKI.createCaStore([root]);
        ['forge', 'node'].forEach(function(name) {
          var run = _runChain(store, [leaf], {
            verificationBackend: name,
            validityCheckDate: FIXTURE_DATE
          });
          ASSERT.ifError(run.thrown);
          ASSERT.equal(run.result, true, 'backend: ' + name);
        });
      });

      itNode('should reject PSS certificates whose parameters weaken ' +
        'the policy', function() {
        // the fixture uses the RFC 4056 defaults (SHA-1); the
        // signature itself is valid, but the certificate may not
        // lower the security policy via its own parameters
        ASSERT.throws(function() {
          PKI.verifyCertificateSignature(
            FIXTURES.pssSha1Pem, FIXTURES.pssSha1Pem,
            {backend: 'node'});
        }, function(e) {
          return e.code === VERR.insecure_signature_parameters &&
              e.stage === 'import';
        });
      });
    });

    describe('parse result caching (node backend)', function() {
      itNode('should reuse immutable parse results for identical ' +
        'certificates', function() {
        var backend = BACKENDS.node;
        backend.clearCache();
        var first = backend.importCertificate(chain.leaf.cert);
        var second = backend.importCertificate(chain.leaf.cert);
        ASSERT.strictEqual(first, second);
        ASSERT.equal(Object.isFrozen(first), true);
        // the record bundles encoding, signature parameters, and
        // key usage together
        ASSERT.equal(typeof first.der, 'string');
        ASSERT.equal(typeof first.signatureOid, 'string');
        ASSERT.ok(first.keyUsage === null ||
            FORGE.util.isArray(first.keyUsage));
      });

      itNode('should key identities by fingerprint, not by name',
        function() {
          var backend = BACKENDS.node;
          var a = backend.importCertificate(chain.rootA.cert);
          var b = backend.importCertificate(chain.rootB.cert);
          // same subject name, different keys and certificates
          ASSERT.notEqual(a.fingerprint, b.fingerprint);
          ASSERT.notEqual(a.keyFingerprint, b.keyFingerprint);
        });

      itNode('should not reuse judgments across backends', function() {
        // populate the node backend cache, then verify with forge:
        // the forge backend must perform its own verification
        BACKENDS.node.clearCache();
        ASSERT.equal(PKI.verifyCertificateSignature(
          chain.intermediate.cert, chain.leaf.cert,
          {backend: 'node'}), true);
        var calls = 0;
        var original = BACKENDS.forge.verifySignature;
        BACKENDS.forge.verifySignature = function() {
          ++calls;
          return original.apply(this, arguments);
        };
        try {
          ASSERT.equal(PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.leaf.cert,
            {backend: 'forge'}), true);
          ASSERT.equal(calls, 1);
        } finally {
          BACKENDS.forge.verifySignature = original;
        }
      });
    });

    describe('error reporting', function() {
      itNode('should report stage and reason without private key ' +
        'material', function() {
        var error;
        try {
          PKI.verifyCertificateSignature(
            chain.intermediate.cert, chain.sha1Leaf.cert,
            {backend: 'node'});
        } catch(e) {
          error = e;
        }
        ASSERT.ok(error, 'expected an error');
        ASSERT.equal(error.code, VERR.unsupported_signature_algorithm);
        ASSERT.equal(typeof error.stage, 'string');
        var report = error.message + JSON.stringify(error);
        ASSERT.equal(/PRIVATE KEY/i.test(report), false);
      });
    });
  });
})();
