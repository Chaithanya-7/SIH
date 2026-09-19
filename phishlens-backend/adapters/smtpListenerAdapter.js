const { SMTPServer } = require('smtp-server');

class SMTPListenerAdapter {
    constructor() {
        this.port = parseInt(process.env.SMTP_LISTEN_PORT || '2525');
        this.host = process.env.SMTP_BIND_HOST || '127.0.0.1';
        this.server = null;
        this.onMailReceived = null;
    }

    start(onMailReceivedCallback) {
        if (process.env.ENABLE_SMTP_INGESTION !== 'true') {
            console.log('ℹ️  [SMTPListener] Disabled. Set ENABLE_SMTP_INGESTION=true and SMTP_USERNAME/SMTP_PASSWORD to enable authenticated SMTP ingestion.');
            return;
        }

        const username = process.env.SMTP_USERNAME;
        const password = process.env.SMTP_PASSWORD;
        if (!username || !password) {
            console.error('❌ [SMTPListener] Refusing to start: SMTP_USERNAME and SMTP_PASSWORD are required.');
            return;
        }

        this.onMailReceived = onMailReceivedCallback;

        this.server = new SMTPServer({
            authOptional: false,
            maxMessageSize: parseInt(process.env.SMTP_MAX_MESSAGE_BYTES || '10485760', 10),
            onAuth: (auth, _session, callback) => {
                if (auth.username === username && auth.password === password) {
                    return callback(null, { user: username });
                }
                return callback(new Error('Invalid SMTP credentials'));
            },
            onData: (stream, session, callback) => {
                let chunks = [];
                let completed = false;
                const finish = (error) => {
                    if (completed) return;
                    completed = true;
                    callback(error);
                };
                stream.on('data', (chunk) => chunks.push(chunk));
                stream.on('error', finish);
                stream.on('end', async () => {
                    const rawEmail = Buffer.concat(chunks).toString('utf8');
                    console.log(`\n📬 [SMTPListener] Intercepted new incoming raw email on ${this.host}:${this.port}! (${rawEmail.length} bytes)`);

                    try {
                        if (this.onMailReceived) {
                            await this.onMailReceived(rawEmail, 'SMTP_GATEWAY');
                        }
                        finish();
                    } catch (error) {
                        console.error('[SMTPListener] Pipeline rejected message:', error.message);
                        finish(new Error('Message processing failed'));
                    }
                });
            }
        });

        this.server.listen(this.port, this.host, () => {
            console.log(`✅ [SMTPListener] Active Local SMTP Gateway listening on ${this.host}:${this.port}`);
        });

        this.server.on('error', (err) => {
            console.error('[SMTPListener] Server error:', err.message);
        });
    }
}

module.exports = new SMTPListenerAdapter();
