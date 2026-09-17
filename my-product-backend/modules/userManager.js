const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class UserManager {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/users.json');
        this.sessionsFile = path.join(__dirname, '../data/sessions.json');
        this.users = new Map();
        this.sessions = new Map(); // sessionToken -> userId
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
                list.forEach(u => this.users.set(u.id, u));
            }

            if (fs.existsSync(this.sessionsFile)) {
                const rawSess = fs.readFileSync(this.sessionsFile, 'utf8');
                const listSess = JSON.parse(rawSess || '[]');
                listSess.forEach(s => this.sessions.set(s.token, s));
            }

            console.log(`[UserManager] Loaded ${this.users.size} user(s) and ${this.sessions.size} session(s) from disk.`);
        } catch (e) {
            console.error('[UserManager] Error loading user storage:', e.message);
        }
    }

    saveStorage() {
        try {
            const userList = Array.from(this.users.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(userList, null, 2), 'utf8');

            const sessList = Array.from(this.sessions.values());
            fs.writeFileSync(this.sessionsFile, JSON.stringify(sessList, null, 2), 'utf8');
        } catch (e) {
            console.error('[UserManager] Error saving user storage:', e.message);
        }
    }

    findOrCreateFromGoogleProfile({ googleAccountId, email, name, avatarUrl }) {
        if (!email) throw new Error('Email is required for user creation.');
        const cleanEmail = email.trim().toLowerCase();

        // Search existing user by googleAccountId or email
        let user = Array.from(this.users.values()).find(
            u => u.google_account_id === googleAccountId || u.email.toLowerCase() === cleanEmail
        );

        const now = new Date().toISOString();

        if (!user) {
            user = {
                id: `usr_${crypto.randomBytes(8).toString('hex')}`,
                google_account_id: googleAccountId || `g_${crypto.randomBytes(6).toString('hex')}`,
                email: cleanEmail,
                name: name || cleanEmail.split('@')[0],
                avatar_url: avatarUrl || '',
                organization_id: null,
                role: 'EMPLOYEE',
                created_at: now,
                updated_at: now
            };
            this.users.set(user.id, user);
        } else {
            user.google_account_id = googleAccountId || user.google_account_id;
            user.name = name || user.name;
            user.avatar_url = avatarUrl || user.avatar_url;
            user.updated_at = now;
        }

        // Issue application's own SecureMail session
        const sessionToken = `sm_sess_${crypto.randomBytes(24).toString('hex')}`;
        const sessionRecord = {
            token: sessionToken,
            user_id: user.id,
            created_at: now,
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
        };

        this.sessions.set(sessionToken, sessionRecord);
        this.saveStorage();

        return { user, sessionToken };
    }

    getUserBySessionToken(token) {
        if (!token) return null;
        const session = this.sessions.get(token);
        if (!session) return null;

        if (new Date(session.expires_at).getTime() < Date.now()) {
            this.sessions.delete(token);
            this.saveStorage();
            return null;
        }

        return this.users.get(session.user_id) || null;
    }

    getUserById(userId) {
        return this.users.get(userId) || null;
    }

    updateUser(user) {
        if (!user || !user.id) return;
        user.updated_at = new Date().toISOString();
        this.users.set(user.id, user);
        this.saveStorage();
        return user;
    }

    getAllUsersInOrg(orgId) {
        if (!orgId) return [];
        return Array.from(this.users.values()).filter(u => u.organization_id === orgId);
    }
}

module.exports = new UserManager();
