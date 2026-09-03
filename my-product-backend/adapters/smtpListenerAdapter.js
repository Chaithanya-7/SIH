const { SMTPServer } = require('smtp-server');

class SMTPListenerAdapter {
    constructor() {
        this.port = process.env.SMTP_LISTEN_PORT || 2525;
        this.server = null;
        this.onMailReceived = null;
    }

    start(onMailReceivedCallback) {
        this.onMailReceived = onMailReceivedCallback;

        this.server = new SMTPServer({
            disabledCommands: ['AUTH'], // Allow unauthenticated local mail delivery for demo
            onData: (stream, session, callback) => {
                let chunks = [];
                stream.on('data', (chunk) => chunks.push(chunk));
                stream.on('end', () => {
                    const rawEmail = Buffer.concat(chunks).toString('utf8');
                    console.log(`\n📬 [SMTPListener] Intercepted new incoming raw email on port ${this.port}! (${rawEmail.length} bytes)`);

                    if (this.onMailReceived) {
                        this.onMailReceived(rawEmail, 'SMTP_GATEWAY');
                    }

                    callback();
                });
            }
        });

        this.server.listen(this.port, () => {
            console.log(`✅ [SMTPListener] Active Local SMTP Ingestion Gateway listening on port ${this.port}`);
        });

        this.server.on('error', (err) => {
            console.error('[SMTPListener] Server error:', err.message);
        });
    }
}

module.exports = new SMTPListenerAdapter();
