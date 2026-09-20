const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { dataFile } = require('./dataPaths');

class MailboxConnectionManager {
    constructor() {
        this.storageFile = dataFile('mailbox_connections.json');
        this.connections = new Map(); // id -> connection
        this.loadStorage();
    }

    loadStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }

            if (fs.existsSync(this.storageFile)) {
                const raw = fs.readFileSync(this.storageFile, 'utf8');
                const list = JSON.parse(raw || '[]');
                list.forEach(c => this.connections.set(c.id, c));
            }

            console.log(`[MailboxConnectionManager] Loaded ${this.connections.size} mailbox connection(s) from disk.`);
        } catch (e) {
            console.error('[MailboxConnectionManager] Error loading mailbox connections:', e.message);
        }
    }

    saveStorage() {
        try {
            const list = Array.from(this.connections.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(list, null, 2), 'utf8');
        } catch (e) {
            console.error('[MailboxConnectionManager] Error saving mailbox connections:', e.message);
        }
    }

    saveConnection({ userId, organizationId, providerAccount, providerUserId, status = 'CONNECTED', historyId = null, watchExpiration = null }) {
        if (!userId || !providerAccount) {
            throw new Error('userId and providerAccount email are required.');
        }

        const cleanMailbox = providerAccount.trim().toLowerCase();
        let connection = Array.from(this.connections.values()).find(
            c => c.user_id === userId || c.provider_account.toLowerCase() === cleanMailbox
        );

        const now = new Date().toISOString();

        if (!connection) {
            connection = {
                id: `mbx_${crypto.randomBytes(8).toString('hex')}`,
                user_id: userId,
                organization_id: organizationId || null,
                provider: 'GMAIL',
                provider_account: cleanMailbox,
                provider_user_id: providerUserId || null,
                status: status,
                history_id: historyId || null,
                watch_expiration: watchExpiration || null,
                created_at: now,
                updated_at: now
            };
            this.connections.set(connection.id, connection);
        } else {
            connection.user_id = userId;
            connection.organization_id = organizationId || connection.organization_id;
            connection.provider_account = cleanMailbox;
            connection.provider_user_id = providerUserId || connection.provider_user_id;
            connection.status = status;
            connection.history_id = historyId || connection.history_id;
            connection.watch_expiration = watchExpiration || connection.watch_expiration;
            connection.updated_at = now;
        }

        this.saveStorage();
        return connection;
    }

    getConnectionByUser(userId) {
        return Array.from(this.connections.values()).find(c => c.user_id === userId) || null;
    }

    getConnectionByMailbox(providerAccount) {
        if (!providerAccount) return null;
        const clean = providerAccount.trim().toLowerCase();
        return Array.from(this.connections.values()).find(c => c.provider_account.toLowerCase() === clean) || null;
    }

    /**
     * Every connected mailbox, across organisations.
     *
     * Added because the Gmail adapter's readiness check called it, found it
     * absent, and had a `typeof === 'function'` guard that quietly substituted
     * an empty list. The guard meant the check could never see a connected
     * mailbox: it reported "not configured" permanently, and the Mail Coverage
     * view - whose entire job is answering whether mail could arrive
     * unexamined - said Gmail was not being watched while it was.
     *
     * Callers that must respect organisation isolation use
     * getAllConnectionsInOrg. This one is for asking about the installation as
     * a whole.
     */
    getAllConnections() {
        return Array.from(this.connections.values());
    }

    getAllConnectionsInOrg(orgId) {
        if (!orgId) return [];
        return Array.from(this.connections.values()).filter(c => c.organization_id === orgId);
    }

    updateStatus(connectionId, status, errorReason = null) {
        const connection = this.connections.get(connectionId);
        if (connection) {
            connection.status = status;
            if (errorReason) connection.error_reason = errorReason;
            connection.updated_at = new Date().toISOString();
            this.saveStorage();
        }
        return connection;
    }

    updateHistoryCheckpoint(connectionId, historyId) {
        const connection = this.connections.get(connectionId);
        if (connection && historyId) {
            connection.history_id = String(historyId);
            connection.updated_at = new Date().toISOString();
            this.saveStorage();
        }
        return connection;
    }
}

module.exports = new MailboxConnectionManager();
