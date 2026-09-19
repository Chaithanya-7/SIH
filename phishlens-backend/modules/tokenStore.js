const fs = require('fs');
const path = require('path');

class TokenStore {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/tokens.json');
        this.tokens = new Map(); // userId -> tokenData
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
                list.forEach(t => {
                    if (t.user_id) {
                        this.tokens.set(t.user_id, t);
                    }
                });
            }

            console.log(`[TokenStore] Loaded ${this.tokens.size} local secure runtime token record(s) from disk.`);
        } catch (e) {
            console.error('[TokenStore] Error loading token storage:', e.message);
        }
    }

    saveStorage() {
        try {
            const list = Array.from(this.tokens.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(list, null, 2), 'utf8');
        } catch (e) {
            console.error('[TokenStore] Error saving token storage:', e.message);
        }
    }

    saveTokens(userId, mailboxEmail, tokenData) {
        if (!userId) throw new Error('userId is required for token storage.');

        const existing = this.tokens.get(userId) || {};
        const updated = {
            user_id: userId,
            mailbox_email: mailboxEmail || existing.mailbox_email || '',
            access_token: tokenData.access_token || existing.access_token || '',
            refresh_token: tokenData.refresh_token || existing.refresh_token || '',
            expiry_date: tokenData.expiry_date || (Date.now() + (tokenData.expires_in || 3600) * 1000),
            token_type: tokenData.token_type || 'Bearer',
            scope: tokenData.scope || existing.scope || 'https://www.googleapis.com/auth/gmail.readonly',
            updated_at: new Date().toISOString()
        };

        this.tokens.set(userId, updated);
        this.saveStorage();
        return { user_id: userId, mailbox_email: updated.mailbox_email, has_refresh_token: !!updated.refresh_token };
    }

    getTokens(userId) {
        return this.tokens.get(userId) || null;
    }

    getTokensByMailbox(mailboxEmail) {
        if (!mailboxEmail) return null;
        const clean = mailboxEmail.trim().toLowerCase();
        return Array.from(this.tokens.values()).find(t => t.mailbox_email.toLowerCase() === clean) || null;
    }

    revokeTokens(userId) {
        if (this.tokens.has(userId)) {
            this.tokens.delete(userId);
            this.saveStorage();
            return true;
        }
        return false;
    }
}

module.exports = new TokenStore();
