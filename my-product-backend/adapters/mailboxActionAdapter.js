const gmailMailboxAdapter = require('./gmailMailboxAdapter');
const simulationMailboxAdapter = require('./simulationMailboxAdapter');

class MailboxActionAdapter {
    getAdapter() {
        const mode = (process.env.REMEDIATION_MODE || 'simulation').toLowerCase();
        const provider = (process.env.MAILBOX_PROVIDER || 'gmail').toLowerCase();

        if (mode === 'live' && provider === 'gmail') {
            return gmailMailboxAdapter;
        }
        return simulationMailboxAdapter;
    }

    async quarantineMessage(target) {
        const adapter = this.getAdapter();
        return await adapter.quarantineMessage(target);
    }

    async restoreMessage(target) {
        const adapter = this.getAdapter();
        return await adapter.restoreMessage(target);
    }

    async verifyMessageState(target, expectedState) {
        const adapter = this.getAdapter();
        return await adapter.verifyMessageState(target, expectedState);
    }
}

module.exports = new MailboxActionAdapter();
