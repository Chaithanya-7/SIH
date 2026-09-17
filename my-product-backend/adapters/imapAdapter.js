require('dotenv').config();
const fs = require('fs');
const path = require('path');
const Imap = require('imap');

class IMAPAdapter {
    constructor() {
        this.enabled = process.env.IMAP_ENABLED === 'true';
        this.config = {
            user: process.env.IMAP_USER || '',
            password: process.env.IMAP_PASSWORD || '',
            host: process.env.IMAP_HOST || 'imap.gmail.com',
            port: parseInt(process.env.IMAP_PORT || '993'),
            tls: true,
            tlsOptions: { rejectUnauthorized: false }
        };
        this.onMailReceived = null;
        this.stateFile = path.join(__dirname, '../data/imap_state.json');
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
            return;
        }

        console.log(`📡 [IMAPAdapter] IMAP worker started for ${this.config.user} on ${this.config.host} (Last UID: ${this.lastProcessedUid})...`);

        const pollNewMessages = () => {
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

                        f.on('message', (msg, seqno) => {
                            let currentUid = 0;
                            msg.once('attributes', (attrs) => {
                                currentUid = attrs.uid;
                            });

                            msg.on('body', (stream) => {
                                let buffer = '';
                                stream.on('data', (chunk) => buffer += chunk.toString('utf8'));
                                stream.once('end', async () => {
                                    if (this.onMailReceived) {
                                        try {
                                            await this.onMailReceived(buffer, 'IMAP_INBOX', null, currentUid);
                                            if (currentUid > 0) {
                                                this.saveLastUid(currentUid);
                                            }
                                        } catch (err) {
                                            console.error(`[IMAPAdapter] Pipeline execution failed for UID ${currentUid}, UID state not advanced:`, err.message);
                                        }
                                    }
                                });
                            });
                        });

                        f.once('end', () => {
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
                this.isProcessing = false;
            });

            imap.connect();
        };

        // Poll inbox safely every 12 seconds
        if (this.pollInterval) clearInterval(this.pollInterval);
        this.pollInterval = setInterval(pollNewMessages, 12000);
        pollNewMessages();
    }
}

module.exports = new IMAPAdapter();
