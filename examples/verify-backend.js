/**
 * Example: selecting a certificate signature verification backend.
 *
 * Demonstrates:
 * - the default pure-JS ('forge') backend, which also runs in browsers
 * - the 'node' backend, which delegates signature verification to the
 *   Node.js built-in crypto module (Node.js >= 15.6)
 * - checking backend availability and handling typed errors
 * - verifying a chain with an explicitly selected backend and an
 *   injected verification time
 *
 * Run with: node examples/verify-backend.js
 */
var forge = require('..');
var pki = forge.pki;

// --- build a small local chain (root CA -> server certificate) -------
var rootKeys = pki.rsa.generateKeyPair(2048);
var root = pki.createCertificate();
root.publicKey = rootKeys.publicKey;
root.serialNumber = '01';
root.validity.notBefore = new Date();
root.validity.notAfter = new Date();
root.validity.notAfter.setFullYear(
  root.validity.notBefore.getFullYear() + 10);
var rootAttrs = [{name: 'commonName', value: 'Example Root CA'}];
root.setSubject(rootAttrs);
root.setIssuer(rootAttrs);
root.setExtensions([
  {name: 'basicConstraints', cA: true, critical: true},
  {name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true}
]);
root.sign(rootKeys.privateKey, forge.md.sha256.create());

var serverKeys = pki.rsa.generateKeyPair(2048);
var server = pki.createCertificate();
server.publicKey = serverKeys.publicKey;
server.serialNumber = '02';
server.validity.notBefore = new Date();
server.validity.notAfter = new Date();
server.validity.notAfter.setFullYear(
  server.validity.notBefore.getFullYear() + 2);
server.setSubject([{name: 'commonName', value: 'server.example.test'}]);
server.setIssuer(root.subject.attributes);
server.setExtensions([
  {name: 'basicConstraints', cA: false, critical: true},
  {name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
    critical: true}
]);
server.sign(rootKeys.privateKey, forge.md.sha256.create());

// the trust anchors are always provided by the caller
var caStore = pki.createCaStore([root]);

// --- 1. default backend (pure JS, browser-compatible) ----------------
var ok = pki.verifyCertificateChain(caStore, [server]);
console.log('default (forge) backend, chain verified:', ok);

// --- 2. explicit backend selection -----------------------------------
// check availability first if the runtime is unknown
var nodeBackend = pki.getCertificateVerificationBackend('node');
if(nodeBackend.isAvailable()) {
  ok = pki.verifyCertificateChain(caStore, [server], {
    verificationBackend: 'node',
    // the verification time can be injected (eg: for testing or for
    // validating at a specific point in time)
    validityCheckDate: new Date()
  });
  console.log('node backend, chain verified:', ok);

  // single signature check; the node backend also accepts PEM/DER
  // directly, including algorithms forge cannot parse (eg: ECDSA)
  console.log('node backend, signature valid:',
    pki.verifyCertificateSignature(
      pki.certificateToPem(root), pki.certificateToPem(server),
      {backend: 'node'}));
} else {
  console.log('node backend not available in this runtime; ' +
    'use the forge backend (pure JS).');
}

// --- 3. typed errors --------------------------------------------------
// errors carry a recognizable code and the stage at which they
// occurred; a selected backend is never silently replaced by another
try {
  pki.verifyCertificateChain(caStore, [server], {
    verificationBackend: 'node',
    validityCheckDate: new Date('2040-01-01')
  });
} catch(e) {
  if(pki.isCertificateVerificationError(e)) {
    // backend-level problem (unavailable, unsupported algorithm, ...)
    console.log('backend error:', e.code, 'stage:', e.stage);
  } else {
    // ordinary chain policy failure
    console.log('chain rejected:', e.error, '-', e.message);
  }
}
