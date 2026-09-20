const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');
const { dataFile } = require('./dataPaths');
const secretStore = require('./secretStore');

/**
 * Signing in with Google, on the user's own machine and on their own credential.
 *
 * No longer used to connect a mailbox for reading - watching the browser sees
 * the same mail sooner and needs no credential at all. What still needs a
 * Google sign-in is acting on a message: moving one out of an inbox requires a
 * token that IMAP read access does not provide.
 *
 * Google will not let anybody obtain a token without a registered OAuth client,
 * so somebody has to own one. The choice is between shipping ours inside every
 * copy of the application - which makes every install depend on us, and hands a
 * distributed secret to anyone who unzips the package - and asking the operator
 * for a client of their own, which is free and takes a few minutes. This does
 * the second, and the console walks through it.
 *
 * The flow is the loopback redirect Google documents for installed
 * applications: consent happens in the real browser, Google redirects to a
 * localhost address this server is already listening on, and the code is
 * exchanged here. PKCE (RFC 7636) is used throughout, so possession of the
 * authorization code is not enough to obtain a token - which is what makes a
 * desktop client safe despite its "secret" not really being one.
 *
 * What is stored: the refresh token, encrypted. Access tokens are short-lived
 * and kept in memory only.
 */

const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const REVOKE_ENDPOINT = 'https://oauth2.googleapis.com/revoke';

// Gmail's IMAP has no read-only scope.
//
// https://mail.google.com/ is the only scope that grants IMAP access, and it
// carries full mailbox access - including deletion. gmail.readonly works with
// the Gmail API but not with IMAP, so authenticating the existing poller costs
// this. Both entries are the same value on purpose: pretending there is a
// narrower one here would put a reassuring label on an identical request, and
// the consent screen would still say full access. What the console tells the
// user must match what Google shows them.
const SCOPES = {
    read: ['https://mail.google.com/'],
    modify: ['https://mail.google.com/']
};

// A pending authorisation lives only as long as it takes somebody to click
// through a consent screen. Anything older is abandoned rather than kept.
const STATE_TTL_MS = 10 * 60 * 1000;

class GoogleOAuth {
    constructor() {
        this.configFile = dataFile('google_oauth_client.json');
        this.pending = new Map();
        this.client = this.loadClient();
    }

    // ---------- the operator's own OAuth client ----------

    loadClient() {
        try {
            if (!fs.existsSync(this.configFile)) return null;
            const raw = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
            const secret = raw.secret ? secretStore.decrypt(raw.secret) : null;
            if (!raw.client_id) return null;
            return { clientId: raw.client_id, clientSecret: secret, saved_at: raw.saved_at };
        } catch (e) {
            console.error(`[GoogleOAuth] Stored client could not be read: ${e.message}`);
            return null;
        }
    }

    /**
     * A desktop client's "secret" is not confidential - Google says so, and it
     * ships inside every copy of any installed app. It is accepted because
     * Google's token endpoint still asks for it, and encrypted at rest for the
     * same reason the mailbox passwords are: so a backup or a synced folder
     * does not carry it in the clear. PKCE, not this value, is what protects
     * the exchange.
     */
    saveClient({ clientId, clientSecret }) {
        const id = String(clientId || '').trim();
        if (!id) throw new Error('A client ID is required.');
        if (!/\.apps\.googleusercontent\.com$/.test(id)) {
            throw new Error('That does not look like a Google client ID. It should end in .apps.googleusercontent.com');
        }

        const record = {
            client_id: id,
            secret: clientSecret ? secretStore.encrypt(String(clientSecret).trim()) : null,
            saved_at: new Date().toISOString()
        };
        fs.writeFileSync(this.configFile, JSON.stringify(record, null, 2), { encoding: 'utf8', mode: 0o600 });
        this.client = { clientId: id, clientSecret: clientSecret ? String(clientSecret).trim() : null, saved_at: record.saved_at };
        return this.status();
    }

    forgetClient() {
        try {
            if (fs.existsSync(this.configFile)) fs.unlinkSync(this.configFile);
        } catch (e) {
            console.error(`[GoogleOAuth] Could not remove the stored client: ${e.message}`);
        }
        this.client = null;
        this.pending.clear();
        return this.status();
    }

    status() {
        return {
            configured: !!this.client,
            client_id: this.client ? this.client.clientId : null,
            has_secret: !!(this.client && this.client.clientSecret),
            saved_at: this.client ? this.client.saved_at : null
        };
    }

    // ---------- the flow ----------

    redirectUri(port) {
        // Google permits any port on the loopback address for an installed
        // application, so this follows whatever port the backend actually bound
        // rather than a value that has to be kept in step by hand.
        return `http://127.0.0.1:${port}/api/auth/gmail/callback`;
    }

    /** RFC 7636 §4.1-4.2: a high-entropy verifier and its SHA-256 challenge. */
    createPkcePair() {
        const verifier = crypto.randomBytes(48).toString('base64url');
        const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
        return { verifier, challenge };
    }

    begin({ port, folder = 'INBOX', scope = 'read' }) {
        if (!this.client) {
            const error = new Error('No Google client is configured yet.');
            error.hint = 'Create a free OAuth client in a Google Cloud project and register it with PhishLens first.';
            throw error;
        }

        this.sweepPending();

        const state = crypto.randomBytes(24).toString('base64url');
        const { verifier, challenge } = this.createPkcePair();
        const redirect = this.redirectUri(port);

        this.pending.set(state, { verifier, redirect, folder, created_at: Date.now() });

        const params = new URLSearchParams({
            client_id: this.client.clientId,
            redirect_uri: redirect,
            response_type: 'code',
            scope: SCOPES[scope === 'modify' ? 'modify' : 'read'].join(' '),
            code_challenge: challenge,
            code_challenge_method: 'S256',
            // Without offline access Google returns no refresh token, and the
            // connection would stop working within the hour.
            access_type: 'offline',
            // Google issues a refresh token only on the first consent for a
            // client unless consent is asked for again.
            prompt: 'consent',
            state
        });

        return { url: `${AUTH_ENDPOINT}?${params.toString()}`, state };
    }

    sweepPending() {
        const now = Date.now();
        for (const [state, record] of this.pending) {
            if (now - record.created_at > STATE_TTL_MS) this.pending.delete(state);
        }
    }

    /**
     * Completes the exchange.
     *
     * The state is consumed on use: a code replayed against the same state
     * finds nothing waiting, which is what makes this resistant to an
     * authorization code delivered twice.
     */
    async complete({ code, state }) {
        this.sweepPending();
        const record = this.pending.get(state);
        if (!record) {
            throw new Error('This sign-in link has expired or was already used. Start the sign-in again.');
        }
        this.pending.delete(state);

        if (!this.client) throw new Error('No Google client is configured.');

        const body = new URLSearchParams({
            code,
            client_id: this.client.clientId,
            redirect_uri: record.redirect,
            grant_type: 'authorization_code',
            code_verifier: record.verifier
        });
        if (this.client.clientSecret) body.set('client_secret', this.client.clientSecret);

        const res = await axios.post(TOKEN_ENDPOINT, body.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 20000
        });

        const tokens = res.data || {};
        if (!tokens.refresh_token) {
            throw new Error('Google did not return a refresh token, so this connection could not be kept alive. Remove PhishLens at myaccount.google.com/permissions and try again.');
        }

        const email = this.emailFromIdToken(tokens.id_token) || await this.emailFromUserinfo(tokens.access_token);
        if (!email) throw new Error('Signed in, but Google did not say which account it was.');

        return {
            email,
            refreshToken: tokens.refresh_token,
            accessToken: tokens.access_token,
            expiresIn: tokens.expires_in,
            folder: record.folder
        };
    }

    /**
     * Reads the address out of the ID token without verifying its signature.
     *
     * Deliberate, and safe only because of where this value comes from: the
     * token arrived over TLS directly from Google's token endpoint in response
     * to our own request, not from the browser or the user. It is used to label
     * the connection, never to authenticate anybody. If it were ever accepted
     * from a caller, it would have to be verified against Google's keys first.
     */
    emailFromIdToken(idToken) {
        if (!idToken) return null;
        try {
            const payload = JSON.parse(Buffer.from(String(idToken).split('.')[1], 'base64url').toString('utf8'));
            return payload.email || null;
        } catch (e) {
            return null;
        }
    }

    async emailFromUserinfo(accessToken) {
        if (!accessToken) return null;
        try {
            const res = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
                headers: { Authorization: `Bearer ${accessToken}` },
                timeout: 10000
            });
            return res.data && res.data.email ? res.data.email : null;
        } catch (e) {
            return null;
        }
    }

    async refresh(refreshToken) {
        if (!this.client) throw new Error('No Google client is configured.');
        const body = new URLSearchParams({
            refresh_token: refreshToken,
            client_id: this.client.clientId,
            grant_type: 'refresh_token'
        });
        if (this.client.clientSecret) body.set('client_secret', this.client.clientSecret);

        const res = await axios.post(TOKEN_ENDPOINT, body.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 20000
        });
        return { accessToken: res.data.access_token, expiresIn: res.data.expires_in };
    }

    /** Best-effort: a mailbox is disconnected locally whether or not Google is reachable. */
    async revoke(refreshToken) {
        try {
            await axios.post(REVOKE_ENDPOINT, new URLSearchParams({ token: refreshToken }).toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: 10000
            });
            return true;
        } catch (e) {
            return false;
        }
    }

    /** The SASL XOAUTH2 initial response, as Google documents it for IMAP. */
    static xoauth2(email, accessToken) {
        return Buffer.from(`user=${email}\x01auth=Bearer ${accessToken}\x01\x01`, 'utf8').toString('base64');
    }
}

module.exports = new GoogleOAuth();
module.exports.GoogleOAuth = GoogleOAuth;
