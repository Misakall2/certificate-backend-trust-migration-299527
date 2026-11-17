# Windows environment

Upstream: https://github.com/digitalbazaar/forge

Upstream commit: 01119d67bf65e7898717501ff6417bed9cc37233

Python 3.11.5 and Node.js 24.16.0 are available. Keep local credentials outside this repository.

Runtime uses the included JavaScript code and optional Node.js built-in crypto. Install development dependencies with `npm install --ignore-scripts --no-audit --no-fund`. Run `node node_modules/mocha/bin/_mocha -t 30000 tests/unit/index.js`. Windows cmd does not support the shell variable syntax in the upstream test-node npm script.
