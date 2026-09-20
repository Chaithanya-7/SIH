require('dotenv').config();
const fs = require('fs');
const path = require('path');
const Imap = require('imap');
const ingestionRegistry = require('../modules/ingestionRegistry');
const { dataFile } = require('../modules/dataPaths');

class IMAPAdapter {
    constructor() {
        this.enabled = process.env.IMAP_ENABLED === 'true';
        this.config = {
            user: process.env.IMAP_USER || '',
            password: process.env.IMAP_PASSWORD || '',
            host: process.env.IMAP_HOST || 'imap.gmail.com',
            port: parseInt(process.env.IMAP_PORT || '993'),
            tls: true,
            // Do not silently accept an intercepted or invalid TLS certificate.
            // A lab server with a private CA must opt in explicitly.
            tlsOptions: { rejectUnauthorized: process.env.IMAP_ALLOW_INVALID_CERT !== 'true' }
        };
        this.onMailReceived = null;
        this.stateFile = dataFile('imap_state.json');
        this.lastProcessedUid = this.loadLastUid();
        this.isProcessing = false;
        this.pollInterval = null;
    }

    loadLastUid() {
        try {
            if (fs.existsSync(this.stateFile)) {
                const data = JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
                return data.last_uid || 0;
            }
        } catch (e) {
            console.error('[IMAPAdapter] Error loading IMAP state:', e.message);
        }
        return 0;
    }

    saveLastUid(uid) {
        try {
            this.lastProcessedUid = Math.max(this.lastProcessedUid, uid);
            const dataDir = path.dirname(this.stateFile);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            fs.writeFileSync(this.stateFile, JSON.stringify({ last_uid: this.lastProcessedUid, updated_at: new Date().toISOString() }, null, 2), 'utf8');
        } catch (e) {
            console.error('[IMAPAdapter] Error saving IMAP state:', e.message);
        }
    }

    start(onMailReceivedCallback) {
        this.onMailReceived = onMailReceivedCallback;

        if (!this.enabled || !this.config.user || !this.config.password) {
            console.log('ℹ️ [IMAPAdapter] IMAP Poller disabled (configure IMAP_ENABLED=true in .env to activate real Gmail/Outlook polling).');
            ingestionRegistry.setState('imap_poller', {
                configured: !!(this.config.user && this.config.password),
                enabled: this.enabled,
                status: ingestionRegistry.STATUS.DISABLED,
                detail: this.enabled
                    ? 'Enabled but IMAP_USER/IMAP_PASSWORD are missing, so no mailbox is being polled.'
                    : 'IMAP polling is switched off. No mailbox is being watched through this path.'
            });
            return;
        }

        console.log(`📡 [IMAPAdapter] IMAP worker started for ${this.config.user} on ${this.config.host} (Last UID: ${this.lastProcessedUid})...`);
        ingestionRegistry.setState('imap_poller', {
            configured: true, enabled: true, status: ingestionRegistry.STATUS.ACTIVE,
            detail: `Polling ${this.config.user} on ${this.config.host} every 12s.`
        });

        const pollNewMessages = () => {
            // Reported every cycle, so a poller that stops is visible as STALLED
            // rather than quietly leaving the mailbox unexamined.
            ingestionRegistry.heartbeat('imap_poller');

            if (this.isProcessing) {
                console.log('ℹ️ [IMAPAdapter] Previous poll cycle still executing. Skipping duplicate poll.');
                return;
            }

            this.isProcessing = true;
            const imap = new Imap(this.config);

            imap.once('ready', () => {
                imap.openBox('INBOX', false, (err, box) => {
                    if (err) {
                        this.isProcessing = false;
                        return imap.end();
                    }

                    // Search for UIDs higher than last processed UID or UNSEEN
                    const searchCriteria = this.lastProcessedUid > 0 
                        ? [`UID`, `${this.lastProcessedUid + 1}:*`]
                        : ['UNSEEN'];

                    imap.search(searchCriteria, (err, uids) => {
                        if (err || !uids || !uids.length) {
                            this.isProcessing = false;
                            return imap.end();
                        }

                        // Filter out already processed UIDs
                        const newUids = uids.filter(u => u > this.lastProcessedUid);
                        if (newUids.length === 0) {
                            this.isProcessing = false;
                            return imap.end();
                        }

                        console.log(`📬 [IMAPAdapter] Found ${newUids.length} new unprocessed message(s) (UIDs: ${newUids.join(', ')})`);

                        const f = imap.fetch(newUids, { bodies: '', struct: true });
                        const processingTasks = [];

                        f.on('message', (msg, seqno) => {
                            let currentUid = 0;
                            let rawMessage = '';
                            let resolveTask;
                            let receivedBody = false;
                            let taskFinished = false;
                            const processingTask = new Promise(resolve => { resolveTask = resolve; });
                            const finishTask = () => {
                                if (!taskFinished) {
                                    taskFinished = true;
                                    resolveTask();
                                }
                            };
                            processingTasks.push(processingTask);

                            msg.once('attributes', (attrs) => {
                                currentUid = attrs.uid;
                            });

                            msg.on('body', (stream) => {
                                receivedBody = true;
                                stream.on('data', (chunk) => rawMessage += chunk.toString('utf8'));
                                stream.once('end', async () => {
                                    try {
                                        if (this.onMailReceived) {
                                            await this.onMailReceived(rawMessage, 'IMAP_INBOX', null, {
                                                provider: 'IMAP',
                                                provider_account: this.config.user,
                                                provider_message_id: String(currentUid),
                                                uid: currentUid,
                                                folder: 'INBOX'
                                            });
                                            ingestionRegistry.recordMessage('imap_poller');
                                            if (currentUid > 0) {
                                                this.saveLastUid(currentUid);
                                            }
                                        }
                                    } catch (err) {
                                        console.error(`[IMAPAdapter] Pipeline execution failed for UID ${currentUid}, UID state not advanced:`, err.message);
                                        ingestionRegistry.recordFailure('imap_poller', err);
                                    } finally {
                                        finishTask();
                                    }
                                });
                            });

                            // A malformed IMAP response without a message body must
                            // not leave the poller locked forever.
                            msg.once('end', () => {
                                if (!receivedBody) finishTask();
                            });
                        });

                        f.once('end', async () => {
                            // Do not release the poll lock or close IMAP before each
                            // message reaches a durable pipeline result/checkpoint.
                            await Promise.all(processingTasks);
                            this.isProcessing = false;
                            imap.end();
                        });

                        f.once('error', (err) => {
                            console.error('[IMAPAdapter] Fetch Error:', err.message);
                            this.isProcessing = false;
                            imap.end();
                        });
                    });
                });
            });

            imap.once('error', (err) => {
                console.error('[IMAPAdapter] Connection Error:', err.message);
                // Surfaced rather than only logged: a mailbox that cannot be
                // reached is a mailbox that is not being watched.
                ingestionRegistry.recordFailure('imap_poller', err);
                ingestionRegistry.setState('imap_poller', {
                    status: ingestionRegistry.STATUS.FAILED,
                    detail: `Cannot reach ${this.config.host}: ${err.message}. This mailbox is not being examined.`
                });
                this.isProcessing = false;
            });

            imap.connect();
        };

        // Poll inbox safely every 12 seconds
        if (this.pollInterval) clearInterval(this.pollInterval);
        // unref'd so a poll timer is never the reason this process refuses to
        // exit. Called directly rather than behind a typeof guard: Node's
        // timers always carry unref, and the guard is the shape that once let a
        // missing method hide here.
        this.pollInterval = setInterval(pollNewMessages, 12000).unref();
        pollNewMessages();
    }
}

module.exports = new IMAPAdapter();
