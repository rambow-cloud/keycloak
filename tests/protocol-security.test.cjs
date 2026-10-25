'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

test('administrator credentials are not forwarded through an HTTP redirect', async () => {
  const { verifyKeycloak } = await import('./keycloak-protocol.mjs');
  let credentialRequests = 0;
  let redirectedRequests = 0;
  const server = http.createServer((request, response) => {
    request.resume();
    if (request.url === '/redirect-target') {
      redirectedRequests++;
      response.writeHead(500).end();
    } else {
      credentialRequests++;
      response.writeHead(307, { Location: '/redirect-target' }).end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(verifyKeycloak({ baseUrl: 'http://127.0.0.1:' + server.address().port, username: 'fixture-admin', password: 'fixture-not-real' }));
    assert.equal(credentialRequests, 1);
    assert.equal(redirectedRequests, 0);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
