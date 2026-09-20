const fs = require('fs');
const crypto = require('crypto');
const Imap = require('imap');
const { dataFile } = require('./dataPaths');
const secretStore = require('./secretStore');
const googleOAuth = require('./googleOAuth');
const { GoogleOAuth: GoogleOAuthClass } = googleOAuth;
const ingestionRegistry = require('./ingestionRegistry');

/**
 * Connecting a real mailbox without needing a Google Cloud project.
 *
 * Gmail's API route requires the operator to register an OAuth application,
 * which is a substantial piece of administrative work and leaves the product
 * unusable until it is done. IMAP needs only an app password, which a person
 * can create in their account settings in under a minute, and it reaches the
 * same mail. That makes it the honest default for getting a real mailbox
 * examined today; OAuth remains available for deployments that want it.
 *
 * Three things this does that the environment-variable path could not:
 *
 *   - **Proves the credentials before storing them.** A saved connection that
 *     silently fails to log in is worse than no connection, because the coverage
 *     view then claims a mailbox is being watched while nothing is read.
 *   - **Encrypts the password.** It has to be replayable to poll, so it cannot
 *     be hashed; it is encrypted at rest and never returned by the API.
 *   - **Starts and stops without a restart.**
 */

/**
 * Providers people actually have, with the settings they would otherwise have
 * to look up. `requiresAppPassword` drives what the interface tells them,
 * because "password rejected" on an account with two-step verification is a
 * confusing way to learn you needed a different kind of password.
 */
/**
 * Which folders each provider exposes, and what to call them.
 *
 * Polling watches one folder per connection. INBOX alone is not the whole
 * story: a phishing message that a provider filed as spam, and that somebody
 * then rescues, never appears in the inbox and so would never be examined.
 * Naming the folders here lets that be an explicit choice rather than a silent
 * gap - the same account can be connected twice, once per folder.
 */
const PROVIDERS = {
    gmail: {
        label: 'Gmail / Google Workspace',
        host: 'imap.gmail.com',
        port: 993,
        requiresAppPassword: true,
        guidance: 'Google does not accept your normal password over IMAP. Turn on 2-Step Verification, then create an App Password at myaccount.google.com/apppasswords and paste the 16-character value here.',
        folders: [
            { path: 'INBOX', label: 'Inbox' },
            { path: '[Gmail]/Spam', label: 'Spam' },
            { path: '[Gmail]/All Mail', label: 'All Mail (everything, including already-read)' }
        ]
    },
    outlook: {
        label: 'Outlook / Microsoft 365',
        host: 'outlook.office365.com',
        port: 993,
        requiresAppPassword: true,
        guidance: 'Microsoft accounts with multi-factor authentication need an app password rather than your normal one. Create it in your account security settings.',
        folders: [
            { path: 'INBOX', label: 'Inbox' },
            { path: 'Junk Email', label: 'Junk Email' }
        ]
    },
    yahoo: {
        label: 'Yahoo Mail',
        host: 'imap.mail.yahoo.com',
        port: 993,
        requiresAppPassword: true,
        guidance: 'Yahoo requires an app password generated in Account Security.',
        folders: [
            { path: 'INBOX', label: 'Inbox' },
            { path: 'Bulk Mail', label: 'Bulk Mail (spam)' }
        ]
    },
    custom: {
        label: 'Other IMAP server',
        host: '',
        port: 993,
        requiresAppPassword: false,
        guidance: 'Enter the IMAP host your provider documents, usually something like imap.example.com on port 993.',
        folders: [
            { path: 'INBOX', label: 'Inbox' }
        ]
    }
};

class MailConnections {
    constructor() {
        this.storageFile = dataFile('mail_connections.json');
        this.connections = new Map();
        this.pollers = new Map();
        this.onMail = null;
        this.load();
    }

    load() {
        try {
            if (!fs.existsSync(this.storageFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.storageFile, 'utf8') || '[]');
            stored.forEach(c => this.connections.set(c.id, c));
            console.log(`[MailConnections] Loaded ${this.connections.size} mailbox connection(s).`);
        } catch (e) {
            console.error('[MailConnections] Could not read stored connections:', e.message);
        }
    }

    save() {
        try {
            fs.writeFileSync(this.storageFile, JSON.stringify([...this.connections.values()], null, 2), 'utf8');
        } catch (e) {
            console.error('[MailConnections] Could not persist connections:', e.message);
        }
    }

    providers() {
        return Object.entries(PROVIDERS).map(([id, p]) => ({
            id,
            label: p.label,
            host: p.host,
            port: p.port,
            requires_app_password: p.requiresAppPassword,
            guidance: p.guidance,
            folders: p.folders || [{ path: 'INBOX', label: 'Inbox' }]
        }));
    }

    /** Never includes the password, in any form. */
    describe(connection) {
        return {
            id: connection.id,
            provider: connection.provider,
            provider_label: PROVIDERS[connection.provider]?.label || connection.provider,
            email: connection.email,
            host: connection.host,
            port: connection.port,
            folder: connection.folder,
            auth: connection.auth || 'password',
            password_hint: connection.password_hint,
            added_at: connection.added_at,
            last_checked_at: connection.last_checked_at || null,
            last_error: connection.last_error || null,
            messages_seen: connection.messages_seen || 0,
            watching: this.pollers.has(connection.id)
        };
    }

    list() {
        return [...this.connections.values()].map(c => this.describe(c));
    }

    /**
     * `credential` is either an app password or a Google access token.
     *
     * Signing in with Google changes only how the session authenticates -
     * SASL XOAUTH2 instead of LOGIN. Everything after that point (folders, UID
     * tracking, coverage reporting) is the same code, which is the reason to
     * authenticate the existing poller rather than build a second one.
     */
    imapConfig(connection, credential, mode = 'password') {
        const base = {
            user: connection.email,
            host: connection.host,
            port: connection.port,
            tls: true,
            authTimeout: 15000,
            // A mailbox connection must not accept an intercepted certificate.
            tlsOptions: { servername: connection.host, rejectUnauthorized: true }
        };
        if (mode === 'oauth') {
            return { ...base, xoauth2: GoogleOAuthClass.xoauth2(connection.email, credential) };
        }
        return { ...base, password: credential };
    }

    /**
     * A usable credential for this connection, refreshing the Google token if
     * that is what it uses.
     *
     * Access tokens last about an hour, so a stored one is always assumed
     * stale; only the refresh token is kept, and only encrypted.
     */
    async credentialFor(connection) {
        if (connection.auth === 'oauth') {
            const refreshToken = secretStore.decrypt(connection.secret);
            if (!refreshToken) return { error: 'The stored Google sign-in could not be read. Reconnect this mailbox.' };
            try {
                const { accessToken } = await googleOAuth.refresh(refreshToken);
                return { credential: accessToken, mode: 'oauth' };
            } catch (e) {
                const detail = e.response?.data?.error_description || e.response?.data?.error || e.message;
                return { error: `Google refused to renew access for this mailbox (${detail}). Sign in again.` };
            }
        }

        const password = secretStore.decrypt(connection.secret);
        if (!password) return { error: 'The stored password could not be decrypted. Reconnect this mailbox.' };
        return { credential: password, mode: 'password' };
    }

    /**
     * Logs in, opens the folder and disconnects.
     *
     * Run before anything is stored, so a connection that cannot work is
     * refused at the point the person can still do something about it, with the
     * server's own words rather than a generic failure.
     */
    test({ email, password, host, port, folder = 'INBOX', accessToken = null }) {
        return new Promise(resolve => {
            let settled = false;
            const done = result => {
                if (settled) return;
                settled = true;
                try { imap.end(); } catch (e) { /* already closing */ }
                resolve(result);
            };

            const imap = new Imap(accessToken
                ? this.imapConfig({ email, host, port }, accessToken, 'oauth')
                : this.imapConfig({ email, host, port }, password));

            imap.once('ready', () => {
                imap.openBox(folder, true, (err, box) => {
                    if (err) {
                        return done({ ok: false, error: `Signed in, but the folder "${folder}" could not be opened: ${err.message}` });
                    }
                    // UIDNEXT is the UID the next arrival will be given, so one
                    // below it is the newest message already here. Reported so a
                    // new connection can start from now rather than from the
                    // beginning of the mailbox.
                    const highestUid = Math.max(0, (box.uidnext || 1) - 1);
                    done({ ok: true, messages_in_folder: box.messages.total, highestUid });
                });
            });

            imap.once('error', err => {
                const message = String(err.message || err);
                // Translated, because "Invalid credentials (Failure)" tells
                // somebody with 2-step verification nothing about what to do.
                if (/Invalid credentials|AUTHENTICATIONFAILED|LOGIN failed/i.test(message)) {
                    return done({
                        ok: false,
                        error: 'The mail server rejected the address or password.',
                        hint: PROVIDERS[this.providerForHost(host)]?.guidance
                    });
                }
                if (/ENOTFOUND|EAI_AGAIN/i.test(message)) {
                    return done({ ok: false, error: `The server "${host}" could not be found. Check the address.` });
                }
                if (/ETIMEDOUT|timed out/i.test(message)) {
                    return done({ ok: false, error: `No response from ${host}:${port}. A firewall may be blocking IMAP.` });
                }
                if (/self.signed|certificate/i.test(message)) {
                    return done({ ok: false, error: `The server presented a certificate that could not be verified: ${message}` });
                }
                done({ ok: false, error: message });
            });

            setTimeout(() => done({ ok: false, error: `No response from ${host}:${port} within 25 seconds.` }), 25000);

            try {
                imap.connect();
            } catch (e) {
                done({ ok: false, error: e.message });
            }
        });
    }

    providerForHost(host) {
        const match = Object.entries(PROVIDERS).find(([, p]) => p.host === host);
        return match ? match[0] : 'custom';
    }

    /** Tests first; stores only what worked. */
    async add({ provider = 'gmail', email, password, host, port, folder = 'INBOX' }) {
        const preset = PROVIDERS[provider] || PROVIDERS.custom;
        const resolvedHost = host || preset.host;
        const resolvedPort = Number(port || preset.port || 993);

        if (!email || !password) throw new Error('An email address and password are both required.');
        if (!resolvedHost) throw new Error('An IMAP server address is required.');
        // Per folder, not per address. One connection watches one folder, and
        // covering both inbox and spam means connecting the same account twice
        // - which the console tells people to do, and which an address-only
        // check made impossible.
        if (this.findByEmailAndFolder(email, folder)) {
            throw new Error(`${email} is already connected for the folder "${folder}".`);
        }

        const probe = await this.test({ email, password, host: resolvedHost, port: resolvedPort, folder });
        if (!probe.ok) {
            const error = new Error(probe.error);
            error.hint = probe.hint;
            throw error;
        }

        const connection = {
            id: `mbx-${crypto.randomBytes(6).toString('hex')}`,
            provider,
            email,
            host: resolvedHost,
            port: resolvedPort,
            folder,
            secret: secretStore.encrypt(password),
            password_hint: require('./secretStore').SecretStore.hint(password),
            added_at: new Date().toISOString(),
            messages_seen: 0,
            // Start from the newest message already present.
            //
            // Starting at zero means the first poll asks for UID 1:* - the whole
            // mailbox - so a real inbox would put years of mail through the
            // pipeline at once, and it contradicts what the console promises:
            // that mail already in the folder is not re-examined.
            last_uid: probe.highestUid || 0
        };

        this.connections.set(connection.id, connection);
        this.save();
        this.startWatching(connection.id);

        return { ...this.describe(connection), messages_in_folder: probe.messages_in_folder };
    }

    findByEmailAndFolder(email, folder) {
        const address = String(email || '').toLowerCase();
        const box = String(folder || 'INBOX');
        return [...this.connections.values()].find(
            c => c.email.toLowerCase() === address && String(c.folder || 'INBOX') === box
        ) || null;
    }

    /**
     * Stores a mailbox authenticated by signing in with Google.
     *
     * The refresh token is what gets kept, because access tokens expire within
     * the hour and a stored one would be useless by the next poll. Proving the
     * session before storing it matters more here than with a password: consent
     * can be granted and the IMAP session still be refused, if IMAP is switched
     * off for the account.
     */
    async addOAuth({ email, refreshToken, accessToken, folder = 'INBOX' }) {
        if (!email || !refreshToken) throw new Error('A Google sign-in did not return enough to connect this mailbox.');

        if (this.findByEmailAndFolder(email, folder)) {
            throw new Error(`${email} is already connected for the folder "${folder}".`);
        }

        const host = PROVIDERS.gmail.host;
        const port = PROVIDERS.gmail.port;

        const probe = await this.test({ email, host, port, folder, accessToken });
        if (!probe.ok) {
            const error = new Error(probe.error);
            error.hint = probe.hint || 'Gmail must have IMAP switched on: Gmail settings, "Forwarding and POP/IMAP", Enable IMAP.';
            throw error;
        }

        const connection = {
            id: `mbx-${crypto.randomBytes(6).toString('hex')}`,
            provider: 'gmail',
            auth: 'oauth',
            email,
            host,
            port,
            folder,
            secret: secretStore.encrypt(refreshToken),
            password_hint: 'Signed in with Google',
            added_at: new Date().toISOString(),
            messages_seen: 0,
            // Start from the newest message already present.
            //
            // Starting at zero means the first poll asks for UID 1:* - the whole
            // mailbox - and a real inbox would put years of mail through the
            // pipeline at once. It also contradicts what the console promises:
            // that mail already in the folder is not re-examined.
            last_uid: probe.highestUid || 0
        };

        this.connections.set(connection.id, connection);
        this.save();
        this.startWatching(connection.id);

        return { ...this.describe(connection), messages_in_folder: probe.messages_in_folder };
    }

    remove(id) {
        const connection = this.connections.get(id);
        if (!connection) throw new Error('That mailbox is not connected.');
        this.stopWatching(id);
        this.connections.delete(id);
        this.save();
        // Published again after the delete: stopWatching runs while this
        // connection is still in the map, so on its own it would report the
        // last removed mailbox as failing rather than as gone.
        this.publishCoverage();
        return { removed: connection.email };
    }

    setPipeline(onMail) {
        this.onMail = onMail;
        // Anything stored from a previous run starts watching again.
        this.connections.forEach(c => this.startWatching(c.id));
        // Stated even when there is nothing to watch, so the coverage page
        // reports a deliberate "nothing connected" rather than a default.
        this.publishCoverage();
    }

    startWatching(id) {
        const connection = this.connections.get(id);
        if (!connection || this.pollers.has(id) || !this.onMail) return;

        const poll = () => this.pollOnce(id).catch(e => {
            console.error(`[MailConnections] Poll failed for ${connection.email}: ${e.message}`);
        });

        poll();
        // unref'd so a poll timer never keeps the process alive on its own.
        // Node's timers always carry unref, so it is called directly - guarding
        // it with a typeof check is the pattern that let a missing method hide
        // in this codebase once already.
        const timer = setInterval(poll, 30000).unref();
        this.pollers.set(id, timer);
        this.publishCoverage();

        console.log(`[MailConnections] Watching ${connection.email} on ${connection.host} (${connection.folder}).`);
    }

    stopWatching(id) {
        const timer = this.pollers.get(id);
        if (timer) clearInterval(timer);
        this.pollers.delete(id);
        this.publishCoverage();
    }

    /**
     * Report what is actually being watched to the coverage registry.
     *
     * The registry decides a path's status from setState, not from heartbeats,
     * and nothing here ever called it - so connecting a mailbox through the
     * console left the coverage page still reporting the IMAP path as DISABLED
     * and no live mail being monitored. That page exists precisely to answer
     * "could a message reach somebody without being examined", and it was
     * answering it wrongly in the one direction that matters: claiming less
     * coverage than there was, which trains people to ignore it.
     */
    publishCoverage() {
        const watching = this.pollers.size;
        const failing = Array.from(this.connections.values()).filter(c => c.last_error).length;

        let status;
        if (watching > 0) status = 'ACTIVE';
        else if (this.connections.size > 0) status = 'FAILED';
        else status = 'DISABLED';

        const detail = this.connections.size === 0
            ? 'No mailbox is signed in. The browser extension sees the same mail sooner and needs no credentials.'
            : `${watching} of ${this.connections.size} connected mailbox(es) being polled${failing ? `, ${failing} failing` : ''}.`;

        try {
            ingestionRegistry.setState('imap_poller', {
                configured: this.connections.size > 0,
                enabled: watching > 0,
                status,
                detail
            });
        } catch (e) {
            console.error(`[MailConnections] Could not publish coverage: ${e.message}`);
        }
    }

    /**
     * Reads messages newer than the last one handled.
     *
     * Only new mail, and only once: the highest UID seen is stored, so a
     * restart does not re-analyse a mailbox from the beginning and produce a
     * flood of duplicate cases.
     */
    pollOnce(id) {
        return new Promise(async (resolve, reject) => {
            const connection = this.connections.get(id);
            if (!connection) return resolve({ skipped: 'connection removed' });

            const resolved = await this.credentialFor(connection);
            if (resolved.error) {
                connection.last_error = resolved.error;
                this.save();
                this.publishCoverage();
                return resolve({ skipped: 'credential unavailable' });
            }
            const password = resolved.credential;
            const authMode = resolved.mode;

            const imap = new Imap(this.imapConfig(connection, password, authMode));
            let handled = 0;
            let highestHandled = connection.last_uid || 0;

            imap.once('ready', () => {
                imap.openBox(connection.folder, true, (err) => {
                    if (err) { imap.end(); return reject(err); }

                    const since = (connection.last_uid || 0) + 1;
                    imap.search([['UID', `${since}:*`]], (searchErr, uids) => {
                        if (searchErr) { imap.end(); return reject(searchErr); }

                        const fresh = (uids || []).filter(u => u > (connection.last_uid || 0));
                        if (fresh.length === 0) {
                            connection.last_checked_at = new Date().toISOString();
                            connection.last_error = null;
                            this.save();
                            imap.end();
                            return resolve({ examined: 0 });
                        }

                        const fetch = imap.fetch(fresh, { bodies: '', markSeen: false });

                        // Every message's analysis, so the poll can wait for them.
                        //
                        // The fetch stream ends when the last body has been
                        // delivered - it neither knows nor cares that handling a
                        // message is asynchronous. Finalising on `end` alone
                        // therefore ran while the analyses were still in flight:
                        // `handled` was still zero, so the mailbox reported nothing
                        // examined, and `last_uid` had not moved, so the very same
                        // messages came back on the next pass and every pass after
                        // it. The symptom is a connected mailbox that quietly never
                        // monitors anything.
                        const analyses = [];

                        fetch.on('message', (msg, seqno) => {
                            let raw = '';
                            let uid = null;
                            msg.on('attributes', attrs => { uid = attrs.uid; });
                            msg.on('body', stream => {
                                stream.setEncoding('utf8');
                                stream.on('data', chunk => { raw += chunk; });
                            });
                            msg.once('end', () => {
                                analyses.push((async () => {
                                    try {
                                        await this.onMail(raw, `IMAP:${connection.email}`, null, {
                                            provider: 'IMAP',
                                            provider_account: connection.email,
                                            provider_message_id: String(uid),
                                            uid,
                                            folder: connection.folder,
                                            mailbox_connection_id: connection.id
                                        });
                                        handled++;
                                    } catch (e) {
                                        // Logged and stepped over. One message the
                                        // pipeline chokes on must not wedge the
                                        // mailbox behind it forever, which is what
                                        // leaving the high-water mark unmoved would
                                        // do.
                                        console.error(`[MailConnections] Analysis failed for a message in ${connection.email}: ${e.message}`);
                                    }
                                    if (uid && uid > highestHandled) highestHandled = uid;
                                })());
                            });
                        });

                        fetch.once('error', fetchErr => { imap.end(); reject(fetchErr); });
                        fetch.once('end', async () => {
                            // Nothing is recorded until the work it describes has
                            // actually finished.
                            await Promise.all(analyses);

                            if (highestHandled > (connection.last_uid || 0)) connection.last_uid = highestHandled;
                            connection.messages_seen = (connection.messages_seen || 0) + handled;
                            connection.last_checked_at = new Date().toISOString();
                            connection.last_error = null;
                            this.save();
                            ingestionRegistry.heartbeat('imap_poller');
                            imap.end();
                            resolve({ examined: handled });
                        });
                    });
                });
            });

            imap.once('error', err => {
                connection.last_error = String(err.message || err);
                connection.last_checked_at = new Date().toISOString();
                this.save();
                reject(err);
            });

            imap.connect();
        });
    }

    /** What the coverage view should say about connected mailboxes. */
    coverage() {
        const all = this.list();
        return {
            connected: all.length,
            watching: all.filter(c => c.watching).length,
            failing: all.filter(c => c.last_error).length,
            mailboxes: all
        };
    }
}

module.exports = new MailConnections();
module.exports.PROVIDERS = PROVIDERS;
