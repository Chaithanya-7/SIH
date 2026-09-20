const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

/**
 * Signing in with Google, checked where it can be checked without Google.
 *
 * The parts that matter here are the ones that would fail silently or
 * dangerously: a PKCE challenge that does not actually correspond to its
 * verifier, a state that can be replayed, and an XOAUTH2 string with the wrong
 * separators - which Gmail rejects with an authentication error indi
 * stinguishable from a wrong password.
 */

function fresh() {
    ['../modules/googleOAuth', '../modules/secretStore'].forEach(m => delete require.cache[require.resolve(m)]);
    return require('../modules/googleOAuth');
}

test('the PKCE challenge is the S256 hash of the verifier, in base64url', () => {
    const oauth = fresh();
    const { verifier, challenge } = oauth.createPkcePair();

    // RFC 7636 §4.1: 43-128 characters from the unreserved set.
    assert.ok(verifier.length >= 43 && verifier.length <= 128, `verifier length ${verifier.length} is outside RFC 7636`);
    assert.match(verifier, /^[A-Za-z0-9._~-]+$/, 'the verifier must be unreserved characters only');

    // RFC 7636 §4.2: BASE64URL(SHA256(ASCII(verifier))), unpadded.
    const expected = crypto.createHash('sha256').update(verifier).digest('base64url');
    assert.strictEqual(challenge, expected, 'the challenge must be the S256 hash of this verifier');
    assert.ok(!challenge.includes('='), 'base64url carries no padding');
});

test('two authorisations never share a verifier', () => {
    const oauth = fresh();
    const seen = new Set();
    for (let i = 0; i < 50; i++) seen.add(oauth.createPkcePair().verifier);
    assert.strictEqual(seen.size, 50, 'every authorisation must get its own verifier');
});

test('a sign-in cannot be started before a client is registered, and says how', () => {
    const oauth = fresh();
    oauth.client = null;
    assert.throws(
        () => oauth.begin({ port: 3001 }),
        (e) => {
            assert.match(e.message, /No Google client/i);
            assert.ok(e.hint, 'the refusal must say what to do about it');
            return true;
        }
    );
});

test('the authorisation URL carries PKCE, offline access and the loopback redirect', () => {
    const oauth = fresh();
    oauth.client = { clientId: 'test.apps.googleusercontent.com', clientSecret: 'shh' };

    const { url, state } = oauth.begin({ port: 3456, folder: '[Gmail]/Spam' });
    const parsed = new URL(url);
    const q = parsed.searchParams;

    assert.strictEqual(parsed.origin + parsed.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
    assert.strictEqual(q.get('code_challenge_method'), 'S256');
    assert.ok(q.get('code_challenge'), 'a challenge must be sent');
    assert.strictEqual(q.get('response_type'), 'code');
    // Without offline access Google returns no refresh token and the mailbox
    // would stop being read within the hour.
    assert.strictEqual(q.get('access_type'), 'offline');
    assert.strictEqual(q.get('prompt'), 'consent');
    assert.strictEqual(q.get('redirect_uri'), 'http://127.0.0.1:3456/api/auth/gmail/callback');
    assert.strictEqual(q.get('state'), state);

    // The verifier itself must never travel to the authorisation endpoint -
    // sending it there would defeat the whole exchange.
    assert.ok(!url.includes(oauth.pending.get(state).verifier), 'the verifier must not appear in the URL');

    // The folder chosen before consent has to survive the round trip.
    assert.strictEqual(oauth.pending.get(state).folder, '[Gmail]/Spam');
});

test('a state is single-use, so a replayed authorization code finds nothing waiting', async () => {
    const oauth = fresh();
    oauth.client = { clientId: 'test.apps.googleusercontent.com', clientSecret: 'shh' };
    const { state } = oauth.begin({ port: 3001 });

    assert.ok(oauth.pending.has(state));

    // The first completion consumes it. The network call after that will fail
    // in this test, which is fine: what matters is that the state is gone.
    await oauth.complete({ code: 'irrelevant', state }).catch(() => {});
    assert.ok(!oauth.pending.has(state), 'the state must be consumed on use');

    await assert.rejects(
        () => oauth.complete({ code: 'irrelevant', state }),
        /expired or was already used/i
    );
});

test('an unknown state is refused outright', async () => {
    const oauth = fresh();
    oauth.client = { clientId: 'test.apps.googleusercontent.com' };
    await assert.rejects(
        () => oauth.complete({ code: 'x', state: 'never-issued' }),
        /expired or was already used/i
    );
});

test('a stale authorisation is swept rather than honoured', () => {
    const oauth = fresh();
    oauth.client = { clientId: 'test.apps.googleusercontent.com' };
    const { state } = oauth.begin({ port: 3001 });

    oauth.pending.get(state).created_at = Date.now() - (11 * 60 * 1000);
    oauth.sweepPending();
    assert.ok(!oauth.pending.has(state), 'an authorisation older than its window must not remain usable');
});

test('the XOAUTH2 string matches the SASL format Gmail expects', () => {
    const oauth = fresh();
    const encoded = oauth.GoogleOAuth.xoauth2('someone@example.com', 'ya29.token');
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');

    // Exactly: user=<email>^Aauth=Bearer <token>^A^A
    assert.strictEqual(decoded, 'user=someone@example.com\x01auth=Bearer ya29.token\x01\x01');
    assert.ok(decoded.endsWith('\x01\x01'), 'the two trailing separators are required');
});

test('a client ID that is not a Google one is refused before it can fail confusingly later', () => {
    const oauth = fresh();
    assert.throws(() => oauth.saveClient({ clientId: 'not-a-google-client' }), /apps\.googleusercontent\.com/);
    assert.throws(() => oauth.saveClient({ clientId: '' }), /client ID is required/i);
});

test('the reported status never includes the secret itself', () => {
    const oauth = fresh();
    oauth.client = { clientId: 'test.apps.googleusercontent.com', clientSecret: 'GOCSPX-verysecret' };
    const status = JSON.stringify(oauth.status());
    assert.ok(!status.includes('GOCSPX-verysecret'), 'the client secret must not be reported back');
    assert.match(status, /"has_secret":true/, 'whether one is held may be reported');
});
