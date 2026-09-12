const { SMTPServer } = require('smtp-server');

class SMTPListenerAdapter {
    constructor() {
        this.port = parseInt(process.env.SMTP_LISTEN_PORT || '2525');
        this.host = process.env.SMTP_BIND_HOST || '127.0.0.1';
        this.server = null;
        this.onMailReceived = null;
    }

    start(onMailReceivedCallback) {
        this.onMailReceived = onMailReceivedCallback;

        this.server = new SMTPServer({
            disabledCommands: ['AUTH'], // Allow unauthenticated local loopback delivery for development
            onData: (stream, session, callback) => {
                let chunks = [];
                stream.on('data', (chunk) => chunks.push(chunk));
                stream.on('end', () => {
                    const rawEmail = Buffer.concat(chunks).toString('utf8');
                    console.log(`\n📬 [SMTPListener] Intercepted new incoming raw email on ${this.host}:${this.port}! (${rawEmail.length} bytes)`);

                    if (this.onMailReceived) {
                        this.onMailReceived(rawEmail, 'SMTP_GATEWAY');
                    }

                    callback();
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
