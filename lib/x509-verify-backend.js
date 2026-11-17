/**
 * Selectable certificate signature verification backends for the PKI
 * (X.509) implementation.
 *
 * Two backends are provided:
 *
 * 'forge' -- the classic pure-JavaScript backend. It works in every
 *   runtime that forge itself supports (including browsers) and keeps
 *   the historical verification behavior.
 *
 * 'node' -- a backend that delegates signature verification to the
 *   Node.js built-in crypto module (crypto.X509Certificate and
 *   KeyObject). It requires Node.js >= 15.6. It accepts the same forge
 *   certificate objects as the 'forge' backend and additionally accepts
 *   PEM strings and DER-encoded certificates (binary string, Buffer, or
 *   Uint8Array), which allows certificates whose public key algorithms
 *   the pure-JS parser cannot represent (for example ECDSA) to be
 *   verified.
 *
 * Scope: these backends only verify certificate *signatures*. Chain
 * policy checks (validity period, issuer/subject matching, key usage,
 * basic constraints, path length, name constraints, critical
 * extensions) remain in pki.verifyCertificateChain() and are shared by
 * both backends so that results are comparable. Certificate issuance
 * (signing) is not affected by this module.
 *
 * Security properties:
 *
 * - The 'node' backend uses a fixed allowlist of signature algorithms;
 *   weak algorithms (MD5, SHA-1 based signatures) are rejected even if
 *   the native runtime could verify them.
 * - RSASSA-PSS parameters carried by a certificate are validated
 *   against a fixed policy (SHA-256/384/512 hash, MGF1 with the same
 *   hash, salt length >= 20); a certificate may not weaken the policy
 *   via its own parameters.
 * - Selecting a backend is explicit. If the selected backend is
 *   unavailable or rejects a certificate, the error is reported with a
 *   recognizable code; verification never silently falls back to
 *   another backend.
 * - Caches only hold immutable parse results keyed by SHA-256
 *   fingerprints of the certificate DER (and of the subject public key
 *   info for keys), never by subject/issuer names and never
 *   verification outcomes. No judgment is reused across backends.
 *
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
var forge = require('./forge');
require('./asn1');
require('./oids');
require('./sha256');
require('./util');

// shortcut for asn.1 API
var asn1 = forge.asn1;

/* Public Key Infrastructure (PKI) implementation. */
var pki = module.exports = forge.pki = forge.pki || {};

/**
 * Certificate verification backend error codes. Errors produced by this
 * module carry one of these values in their 'code' property plus a
 * 'stage' property ('backend', 'import', 'parse', or 'verify') that
 * identifies where the failure occurred. Error objects never contain
 * private key material.
 */
pki.certificateVerificationError = {
  backend_unavailable: 'forge.pki.VerificationBackendUnavailable',
  certificate_parse_failed: 'forge.pki.CertificateParseFailed',
  unsupported_signature_algorithm: 'forge.pki.UnsupportedSignatureAlgorithm',
  unsupported_key_algorithm: 'forge.pki.UnsupportedKeyAlgorithm',
  insecure_signature_parameters: 'forge.pki.InsecureSignatureParameters'
};

var _errorCodes = {};
for(var _codeKey in pki.certificateVerificationError) {
  if(pki.certificateVerificationError.hasOwnProperty(_codeKey)) {
    _errorCodes[pki.certificateVerificationError[_codeKey]] = true;
  }
}

/**
 * Returns true if the given error is a typed certificate verification
 * backend error.
 *
 * @param e the error to check.
 *
 * @return true if the error carries a verification backend error code.
 */
pki.isCertificateVerificationError = function(e) {
  return !!(e && e.code && (e.code in _errorCodes));
};

function _verificationError(code, message, props) {
  var error = new Error(message);
  error.code = code;
  if(props) {
    for(var key in props) {
      if(props.hasOwnProperty(key)) {
        error[key] = props[key];
      }
    }
  }
  return error;
}

/**
 * Fixed signature algorithm allowlist for the 'node' backend. Maps
 * signature algorithm OIDs to the expected public key type. Algorithms
 * not listed here (including md5WithRSAEncryption,
 * sha1WithRSAEncryption, DSA, and ECDSA-with-SHA1/SHA-224 variants) are
 * rejected with an unsupported_signature_algorithm error even when the
 * native runtime would accept them.
 */
var _nodeSignatureAllowlist = {
  // RSASSA-PKCS1-v1_5 with SHA-2
  '1.2.840.113549.1.1.11': {name: 'sha256WithRSAEncryption', keyType: 'rsa'},
  '1.2.840.113549.1.1.12': {name: 'sha384WithRSAEncryption', keyType: 'rsa'},
  '1.2.840.113549.1.1.13': {name: 'sha512WithRSAEncryption', keyType: 'rsa'},
  // RSASSA-PSS (parameters validated separately against a fixed policy)
  '1.2.840.113549.1.1.10': {name: 'RSASSA-PSS', keyType: 'rsa', pss: true},
  // ECDSA with SHA-2
  '1.2.840.10045.4.3.2': {name: 'ecdsa-with-SHA256', keyType: 'ec'},
  '1.2.840.10045.4.3.3': {name: 'ecdsa-with-SHA384', keyType: 'ec'},
  '1.2.840.10045.4.3.4': {name: 'ecdsa-with-SHA512', keyType: 'ec'}
};

// hash algorithms accepted inside RSASSA-PSS parameters
var _allowedPssHashes = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512'
};
var _mgf1Oid = '1.2.840.113549.1.1.8';
var _minimumPssSaltLength = 20;

/**
 * Validates RSASSA-PSS parameters carried by a certificate against the
 * fixed policy. The certificate may not weaken the policy via its own
 * parameters.
 *
 * @param params the parsed signature parameters.
 *
 * @throws an insecure_signature_parameters error on policy violations.
 */
function _checkPssParameters(params) {
  params = params || {};
  var hashOid = params.hash && params.hash.algorithmOid;
  var mgfOid = params.mgf && params.mgf.algorithmOid;
  var mgfHashOid =
    params.mgf && params.mgf.hash && params.mgf.hash.algorithmOid;
  if(!(hashOid in _allowedPssHashes)) {
    throw _verificationError(
      pki.certificateVerificationError.insecure_signature_parameters,
      'RSASSA-PSS hash algorithm (OID: ' + hashOid + ') is not allowed; ' +
      'only SHA-256, SHA-384, and SHA-512 are accepted.',
      {stage: 'import', signatureParameters: _safeParams(params)});
  }
  if(mgfOid !== _mgf1Oid) {
    throw _verificationError(
      pki.certificateVerificationError.insecure_signature_parameters,
      'RSASSA-PSS mask generation function (OID: ' + mgfOid + ') is ' +
      'not allowed; only MGF1 is accepted.',
      {stage: 'import', signatureParameters: _safeParams(params)});
  }
  if(mgfHashOid !== hashOid) {
    throw _verificationError(
      pki.certificateVerificationError.insecure_signature_parameters,
      'RSASSA-PSS MGF1 hash algorithm (OID: ' + mgfHashOid + ') must ' +
      'match the PSS hash algorithm (OID: ' + hashOid + ').',
      {stage: 'import', signatureParameters: _safeParams(params)});
  }
  if(typeof params.saltLength !== 'number' ||
    params.saltLength < _minimumPssSaltLength) {
    throw _verificationError(
      pki.certificateVerificationError.insecure_signature_parameters,
      'RSASSA-PSS salt length (' + params.saltLength + ') is below the ' +
      'minimum of ' + _minimumPssSaltLength + ' octets.',
      {stage: 'import', signatureParameters: _safeParams(params)});
  }
}

// returns a plain-data copy of signature parameters for error reports
function _safeParams(params) {
  var copy = {};
  if(params.hash && params.hash.algorithmOid) {
    copy.hash = {algorithmOid: params.hash.algorithmOid};
  }
  if(params.mgf) {
    copy.mgf = {algorithmOid: params.mgf.algorithmOid};
    if(params.mgf.hash && params.mgf.hash.algorithmOid) {
      copy.mgf.hash = {algorithmOid: params.mgf.hash.algorithmOid};
    }
  }
  if(typeof params.saltLength !== 'undefined') {
    copy.saltLength = params.saltLength;
  }
  return copy;
}

/**
 * Computes the SHA-256 fingerprint (hex) of a DER-encoded certificate.
 * Used as the cache key for immutable parse results; names are never
 * used as identity.
 */
function _derFingerprint(der) {
  var md = forge.md.sha256.create();
  md.update(der);
  return md.digest().toHex();
}

function _isForgeCertificate(obj) {
  return !!(obj && typeof obj === 'object' &&
    typeof obj.signatureOid === 'string' && obj.validity &&
    obj.subject && obj.issuer);
}

function _forgeCertToDer(cert) {
  return asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
}

/**
 * Normalizes a supported certificate input to a DER binary string.
 *
 * @param input a PEM string, DER binary string, Buffer, or Uint8Array.
 *
 * @return the DER binary string.
 */
function _inputToDer(input) {
  if(typeof input === 'string') {
    if(input.indexOf('-----BEGIN') !== -1) {
      return _pemToDer(input);
    }
    // assume DER binary string
    return input;
  }
  if(input && typeof input === 'object' &&
    typeof input.length === 'number') {
    // Buffer, Uint8Array, or byte array
    var der = '';
    for(var i = 0; i < input.length; ++i) {
      der += String.fromCharCode(input[i]);
    }
    return der;
  }
  throw _verificationError(
    pki.certificateVerificationError.certificate_parse_failed,
    'Unsupported certificate input; expected a forge certificate, a ' +
    'PEM string, or a DER encoding (binary string, Buffer, or ' +
    'Uint8Array).',
    {stage: 'import'});
}

function _pemToDer(pem) {
  var msg;
  try {
    msg = forge.pem.decode(pem)[0];
  } catch(e) {
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Could not decode PEM certificate: ' + e.message,
      {stage: 'parse'});
  }
  if(!msg || (msg.type !== 'CERTIFICATE' &&
    msg.type !== 'X509 CERTIFICATE' &&
    msg.type !== 'TRUSTED CERTIFICATE')) {
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Could not convert certificate from PEM; PEM header type is ' +
      'not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".',
      {stage: 'parse', headerType: msg && msg.type});
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Could not convert certificate from PEM; PEM is encrypted.',
      {stage: 'parse'});
  }
  return msg.body;
}

/**
 * Parses RSASSA-PSS parameters from their ASN.1 representation,
 * applying the RFC 4056 defaults for absent fields (including a fully
 * empty or absent parameter block, which some encoders emit when all
 * values are defaults).
 *
 * @param paramsAsn1 the parameters ASN.1 object (a SEQUENCE), or null
 *          if the parameter block is absent.
 *
 * @return the parsed parameters.
 */
function _parsePssParameters(paramsAsn1) {
  // RSASSA-PSS-params ::= SEQUENCE {
  //   hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
  //   maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
  //   saltLength         [2] INTEGER           DEFAULT 20,
  //   trailerField       [3] TrailerField      DEFAULT trailerFieldBC }
  var params = {
    hash: {algorithmOid: '1.3.14.3.2.26'},
    mgf: {
      algorithmOid: '1.2.840.113549.1.1.8',
      hash: {algorithmOid: '1.3.14.3.2.26'}
    },
    saltLength: 20
  };
  if(paramsAsn1 === null) {
    return params;
  }
  try {
    if(paramsAsn1.type !== asn1.Type.SEQUENCE || !paramsAsn1.constructed) {
      throw new Error('not a SEQUENCE');
    }
    for(var i = 0; i < paramsAsn1.value.length; ++i) {
      var field = paramsAsn1.value[i];
      if(field.tagClass !== asn1.Class.CONTEXT_SPECIFIC ||
        !field.constructed) {
        throw new Error('unexpected field in RSASSA-PSS parameters');
      }
      if(field.type === 0 || field.type === 1) {
        // [0] EXPLICIT HashAlgorithm / [1] EXPLICIT MaskGenAlgorithm,
        // both AlgorithmIdentifiers
        var ai = field.value[0];
        var algorithmOid = asn1.derToOid(ai.value[0].value);
        if(field.type === 0) {
          params.hash.algorithmOid = algorithmOid;
        } else {
          params.mgf.algorithmOid = algorithmOid;
          if(ai.value.length > 1) {
            // MGF parameters: the hash AlgorithmIdentifier
            params.mgf.hash.algorithmOid =
              asn1.derToOid(ai.value[1].value[0].value);
          }
        }
      } else if(field.type === 2) {
        // [2] EXPLICIT INTEGER
        var hex = forge.util.createBuffer(field.value[0].value).toHex();
        params.saltLength = hex.length === 0 ? 0 : parseInt(hex, 16);
      }
      // [3] trailerField is ignored; only trailerFieldBC (1) is valid
    }
  } catch(e) {
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Could not parse RSASSA-PSS parameters: ' + e.message,
      {stage: 'parse'});
  }
  return params;
}

/**
 * Reads the signature algorithm OID and parameters from a DER-encoded
 * certificate without fully parsing it.
 */
function _readSignatureAlgorithmFromDer(der) {
  var obj;
  try {
    obj = asn1.fromDer(der);
  } catch(e) {
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Could not parse certificate DER: ' + e.message,
      {stage: 'parse'});
  }
  try {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    //   signatureValue }
    var sigAlg = obj.value[1];
    var signatureOid = asn1.derToOid(sigAlg.value[0].value);
    var signatureParameters = {};
    if(signatureOid === '1.2.840.113549.1.1.10') {
      signatureParameters = _parsePssParameters(
        sigAlg.value.length > 1 ? sigAlg.value[1] : null);
    }
    return {
      signatureOid: signatureOid,
      signatureParameters: signatureParameters
    };
  } catch(e) {
    if(pki.isCertificateVerificationError(e)) {
      throw e;
    }
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Could not parse certificate signature algorithm: ' + e.message,
      {stage: 'parse'});
  }
}

/**
 * Reads the subject public key info algorithm OID from a DER-encoded
 * certificate (best effort, used for error reporting).
 *
 * @return the algorithm OID or null if it cannot be determined.
 */
function _readSpkiAlgorithmOidFromDer(der) {
  try {
    var obj = asn1.fromDer(der);
    var tbs = obj.value[0];
    // skip the explicit [0] version field when present
    var offset =
      (tbs.value[0].tagClass === asn1.Class.CONTEXT_SPECIFIC) ? 6 : 5;
    var spki = tbs.value[offset];
    return asn1.derToOid(spki.value[0].value[0].value);
  } catch(e) {
    return null;
  }
}

/**
 * The pure-JavaScript ('forge') verification backend. Always available.
 * Accepts forge certificate objects and PEM strings.
 */
var _forgeBackend = {
  name: 'forge',
  isAvailable: function() {
    return true;
  },
  importCertificate: function(input) {
    if(_isForgeCertificate(input)) {
      return {
        backend: 'forge',
        cert: input,
        fingerprint: _derFingerprint(_forgeCertToDer(input))
      };
    }
    if(typeof input === 'string' && input.indexOf('-----BEGIN') !== -1) {
      // the pure-JS parser only represents RSA public keys; detect
      // other key algorithms up front so they are reported as
      // unsupported rather than as generic parse failures
      var keyOid = _readSpkiAlgorithmOidFromDer(_pemToDer(input));
      if(keyOid !== null && keyOid !== '1.2.840.113549.1.1.1') {
        throw _verificationError(
          pki.certificateVerificationError.unsupported_key_algorithm,
          'The "forge" verification backend does not support the ' +
          'public key algorithm (OID: ' + keyOid + ') used by this ' +
          'certificate; use the "node" verification backend on a ' +
          'supported runtime to verify it.',
          {stage: 'import', keyOid: keyOid});
      }
      var cert;
      try {
        cert = pki.certificateFromPem(input, true);
      } catch(e) {
        if(e.oid || e.signatureOid) {
          throw _verificationError(
            pki.certificateVerificationError.unsupported_key_algorithm,
            'The "forge" verification backend does not support this ' +
            'certificate: ' + e.message,
            {stage: 'import', keyOid: e.oid || e.signatureOid});
        }
        throw _verificationError(
          pki.certificateVerificationError.certificate_parse_failed,
          'Could not parse PEM certificate: ' + e.message,
          {stage: 'parse'});
      }
      return {
        backend: 'forge',
        cert: cert,
        fingerprint: _derFingerprint(_forgeCertToDer(cert))
      };
    }
    throw _verificationError(
      pki.certificateVerificationError.certificate_parse_failed,
      'Unsupported certificate input for the "forge" backend; ' +
      'expected a forge certificate or a PEM string.',
      {stage: 'import'});
  },
  verifySignature: function(parent, child) {
    var p = _forgeBackend.importCertificate(parent);
    var c = _forgeBackend.importCertificate(child);
    // an issuer name mismatch is a failed verification, not an error
    if(!p.cert.issued(c.cert)) {
      return false;
    }
    try {
      return p.cert.verify(c.cert);
    } catch(e) {
      if(e.signatureOid || e.oid) {
        throw _verificationError(
          pki.certificateVerificationError.unsupported_signature_algorithm,
          'The "forge" verification backend does not support the ' +
          'signature algorithm (OID: ' + (e.signatureOid || e.oid) +
          ') used by this certificate: ' + e.message,
          {stage: 'verify', signatureOid: e.signatureOid || e.oid});
      }
      // any other verification error (eg: invalid encryption block
      // from a signature made with a different key) is a failed
      // verification, matching historical chain verification behavior
      return false;
    }
  }
};

// Node.js built-in crypto module; false in browser builds (see the
// "browser" field in package.json) and possibly undefined elsewhere
var _nodeCrypto = null;
try {
  _nodeCrypto = require('crypto');
} catch(e) {
  _nodeCrypto = null;
}

/**
 * Creates the Node.js built-in crypto verification backend.
 *
 * @return the backend object.
 */
function _createNodeBackend() {
  // caches hold immutable parse results only -- never verification
  // outcomes -- and are private to this backend instance so no judgment
  // can leak across backends; entries are keyed by SHA-256 fingerprints
  // of the certificate DER / subject public key info, never by name
  var _parseCache = {};
  var _keyCache = {};

  var backend = {
    name: 'node',

    isAvailable: function() {
      return !!(_nodeCrypto &&
        typeof _nodeCrypto.X509Certificate === 'function' &&
        typeof _nodeCrypto.createPublicKey === 'function' &&
        typeof _nodeCrypto.createHash === 'function');
    },

    clearCache: function() {
      _parseCache = {};
      _keyCache = {};
    },

    /**
     * Imports a certificate into the backend, producing an immutable
     * record that bundles the encoding (DER), the signature algorithm
     * parameters, and the key usage together. Parse failures,
     * unsupported algorithms, and policy-violating signature parameters
     * are reported as distinct typed errors.
     *
     * @param input a forge certificate, PEM string, or DER encoding.
     *
     * @return the frozen import record.
     */
    importCertificate: function(input) {
      var cert = null;
      var der; var signatureOid; var signatureParameters;
      if(_isForgeCertificate(input)) {
        cert = input;
        der = _forgeCertToDer(cert);
        signatureOid = cert.signatureOid;
        signatureParameters = cert.signatureParameters || {};
      } else {
        der = _inputToDer(input);
        var sig = _readSignatureAlgorithmFromDer(der);
        signatureOid = sig.signatureOid;
        signatureParameters = sig.signatureParameters;
      }

      var fingerprint = _derFingerprint(der);
      var cached = _parseCache[fingerprint];
      if(cached) {
        return cached;
      }

      // parse with the native runtime
      var x509;
      try {
        x509 = new _nodeCrypto.X509Certificate(_derToBuffer(der));
      } catch(e) {
        throw _verificationError(
          pki.certificateVerificationError.certificate_parse_failed,
          'The Node.js crypto module could not parse the certificate: ' +
          e.message,
          {stage: 'parse'});
      }

      // enforce the fixed signature algorithm allowlist
      var allowed = _nodeSignatureAllowlist[signatureOid];
      if(!allowed) {
        throw _verificationError(
          pki.certificateVerificationError.unsupported_signature_algorithm,
          'Signature algorithm (OID: ' + signatureOid + ') is not in ' +
          'the "node" verification backend allowlist; weak algorithms ' +
          'such as MD5 and SHA-1 based signatures are rejected.',
          {stage: 'import', signatureOid: signatureOid});
      }
      if(allowed.pss) {
        _checkPssParameters(signatureParameters);
      }

      // the public key must match the key type the signature
      // algorithm expects
      var key = x509.publicKey;
      var keyType = key.asymmetricKeyType;
      var keyTypeOk =
        (allowed.keyType === 'rsa' &&
          (keyType === 'rsa' || keyType === 'rsa-pss')) ||
        (allowed.keyType === 'ec' && keyType === 'ec');
      if(!keyTypeOk) {
        throw _verificationError(
          pki.certificateVerificationError.unsupported_key_algorithm,
          'Public key type "' + keyType + '" cannot be used with ' +
          'signature algorithm ' + allowed.name + '.',
          {stage: 'import', keyType: keyType});
      }

      // key the key cache by the fingerprint of the subject public key
      // info, never by certificate name
      var keyDer; var keyFingerprint;
      try {
        keyDer = key.export({format: 'der', type: 'spki'});
        keyFingerprint = _nodeCrypto.createHash('sha256')
          .update(keyDer).digest('hex');
      } catch(e) {
        throw _verificationError(
          pki.certificateVerificationError.unsupported_key_algorithm,
          'The public key of this certificate cannot be exported by ' +
          'the Node.js crypto module: ' + e.message,
          {stage: 'import', keyType: keyType});
      }

      // key usage as reported by the native parser, when available
      var keyUsage = null;
      try {
        if(forge.util.isArray(x509.keyUsage)) {
          keyUsage = x509.keyUsage.slice();
        }
      } catch(e) {
        keyUsage = null;
      }

      var record = {
        backend: 'node',
        fingerprint: fingerprint,
        der: der,
        signatureOid: signatureOid,
        signatureParameters: signatureParameters,
        keyUsage: keyUsage,
        keyFingerprint: keyFingerprint,
        cert: cert,
        x509: x509
      };
      Object.freeze(record);
      _parseCache[fingerprint] = record;
      _keyCache[keyFingerprint] = key;
      return record;
    },

    /**
     * Verifies the signature on a certificate using the public key of
     * its issuer. Returns false on signature mismatch; throws typed
     * errors for parse failures, unsupported algorithms, and
     * policy-violating parameters. Never falls back to another backend.
     *
     * @param parent the issuer certificate (any supported input).
     * @param child the certificate to verify (any supported input).
     *
     * @return true if the signature is valid, false if it does not
     *           verify.
     */
    verifySignature: function(parent, child) {
      var p = backend.importCertificate(parent);
      var c = backend.importCertificate(child);
      // when both certificates are forge-parsed, an issuer name
      // mismatch is a failed verification, not an error
      if(p.cert && c.cert && !p.cert.issued(c.cert)) {
        return false;
      }
      var key = _keyCache[p.keyFingerprint] || p.x509.publicKey;
      try {
        return c.x509.verify(key);
      } catch(e) {
        // the issuer key cannot be used with the child's signature
        // algorithm; treat as a failed verification
        return false;
      }
    }
  };

  return backend;
}

function _derToBuffer(der) {
  return Buffer.from(der, 'binary');
}

/**
 * The certificate verification backend registry. Custom backends
 * (objects with a verifySignature(parent, child) function and,
 * optionally, isAvailable()/assertAvailable() functions) may be added
 * or passed directly to verification APIs.
 */
pki.certificateVerificationBackends = {
  forge: _forgeBackend,
  node: _createNodeBackend()
};

/**
 * Resolves a verification backend option to a backend object.
 *
 * @param backend a backend name ('forge' or 'node'), a backend object,
 *          or undefined/null for the default ('forge').
 *
 * @return the backend object.
 */
pki.getCertificateVerificationBackend = function(backend) {
  if(backend === undefined || backend === null) {
    backend = 'forge';
  }
  if(typeof backend === 'string') {
    if(!(backend in pki.certificateVerificationBackends)) {
      var names = [];
      for(var name in pki.certificateVerificationBackends) {
        if(pki.certificateVerificationBackends.hasOwnProperty(name)) {
          names.push(name);
        }
      }
      throw new Error(
        'Unknown certificate verification backend "' + backend + '"; ' +
        'available backends: ' + names.join(', ') + '.');
    }
    return pki.certificateVerificationBackends[backend];
  }
  if(typeof backend === 'object' && backend !== null &&
    typeof backend.verifySignature === 'function') {
    return backend;
  }
  throw new Error(
    'Invalid certificate verification backend; expected a backend ' +
    'name or an object with a verifySignature(parent, child) function.');
};

/**
 * Asserts that the given verification backend is usable in this
 * runtime, throwing a recognizable backend_unavailable error if not.
 *
 * @param backend the backend object.
 */
pki.assertCertificateVerificationBackendAvailable = function(backend) {
  if(typeof backend.assertAvailable === 'function') {
    backend.assertAvailable();
    return;
  }
  if(typeof backend.isAvailable === 'function' && !backend.isAvailable()) {
    throw _verificationError(
      pki.certificateVerificationError.backend_unavailable,
      'The certificate verification backend "' +
      (backend.name || 'custom') + '" is not available in this ' +
      'runtime. The "node" backend requires Node.js >= 15.6 with the ' +
      'built-in crypto module; use the "forge" backend for ' +
      'pure-JS/browser verification.',
      {stage: 'backend', backend: backend.name || 'custom'});
  }
};

// the 'forge' backend is always available
_forgeBackend.assertAvailable = function() {};

/**
 * Verifies the signature on a certificate using the public key of its
 * issuer, using the selected verification backend. This is a signature
 * check only; use pki.verifyCertificateChain() for full chain
 * validation.
 *
 * @param parent the issuer certificate (a forge certificate, or -- with
 *          the 'node' backend -- a PEM string or DER encoding).
 * @param child the certificate to verify (same input rules as parent).
 * @param options an object with:
 *          backend the verification backend to use: 'forge' (default),
 *            'node', or a custom backend object.
 *
 * @return true if the signature is valid, false if it does not verify.
 *
 * @throws typed errors (see pki.certificateVerificationError) when the
 *           backend is unavailable, a certificate cannot be parsed, or
 *           an algorithm is not supported by the selected backend.
 */
pki.verifyCertificateSignature = function(parent, child, options) {
  options = options || {};
  var backend = pki.getCertificateVerificationBackend(options.backend);
  pki.assertCertificateVerificationBackendAvailable(backend);
  return backend.verifySignature(parent, child);
};
