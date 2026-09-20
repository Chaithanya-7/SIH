const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { dataFile } = require('./dataPaths');

/**
 * Encrypts secrets that have to be kept in a usable form.
 *
 * A mailbox password is not like a login password. A login password can be
 * hashed, because it only ever needs comparing. A mailbox password has to be
 * presented to the mail server on every poll, so it must be recoverable - which
 * means the honest options are encryption at rest or nothing, and nothing is
 * what this codebase had: tokens.json holds OAuth tokens in plain text.
 *
 * What this protects against is the realistic case: a backup, a synced folder,
 * a support bundle, or someone reading the data directory. It does **not**
 * protect against an attacker who already runs code as this user, because the
 * key sits on the same machine and must be readable by the same process. That
 * limit is stated rather than glossed, because a store that claims more than it
 * delivers is worse than one that admits what it is.
 *
 * AES-256-GCM, so tampering is detected rather than silently decrypting to
 * rubbish.
 */

const ALGORITHM = 'aes-256-gcm';

class SecretStore {
    constructor() {
        this.keyFile = dataFile('secret.key');
        this.key = this.loadOrCreateKey();
    }

    loadOrCreateKey() {
        try {
            if (fs.existsSync(this.keyFile)) {
                const key = Buffer.from(fs.readFileSync(this.keyFile, 'utf8').trim(), 'hex');
                if (key.length === 32) return key;
                console.error('[SecretStore] The stored key is the wrong length; generating a new one. Previously stored secrets will not decrypt.');
            }
        } catch (e) {
            console.error('[SecretStore] Could not read the encryption key:', e.message);
        }

        const key = crypto.randomBytes(32);
        try {
            fs.writeFileSync(this.keyFile, key.toString('hex'), { encoding: 'utf8', mode: 0o600 });
            // Written owner-only. On Windows the mode is advisory, so the real
            // protection there is the per-user application data directory.
            fs.chmodSync(this.keyFile, 0o600);
        } catch (e) {
            console.error('[SecretStore] Could not persist the encryption key, so secrets will not survive a restart:', e.message);
        }
        return key;
    }

    encrypt(plaintext) {
        if (typeof plaintext !== 'string' || plaintext.length === 0) {
            throw new Error('A non-empty value is required.');
        }
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);
        const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        return {
            iv: iv.toString('hex'),
            tag: cipher.getAuthTag().toString('hex'),
            data: encrypted.toString('hex')
        };
    }

    /** Returns null rather than throwing, so one unreadable secret cannot take the service down. */
    decrypt(record) {
        if (!record || !record.iv || !record.tag || !record.data) return null;
        try {
            const decipher = crypto.createDecipheriv(ALGORITHM, this.key, Buffer.from(record.iv, 'hex'));
            decipher.setAuthTag(Buffer.from(record.tag, 'hex'));
            return Buffer.concat([
                decipher.update(Buffer.from(record.data, 'hex')),
                decipher.final()
            ]).toString('utf8');
        } catch (e) {
            console.error('[SecretStore] A stored secret could not be decrypted. It was written with a different key, or it has been altered.');
            return null;
        }
    }

    /** What may safely be shown about a secret: enough to recognise, not enough to use. */
    static hint(plaintext) {
        if (!plaintext) return '';
        const visible = plaintext.slice(-2);
        return `${'•'.repeat(Math.max(4, Math.min(12, plaintext.length - 2)))}${visible}`;
    }

    state() {
        return {
            algorithm: ALGORITHM,
            key_file: this.keyFile,
            limitation: 'Secrets are encrypted at rest against backups, synced folders and anyone reading the data directory. The key lives on this machine and must be readable by this process, so it is not protection against code already running as this user.'
        };
    }
}

module.exports = new SecretStore();
module.exports.SecretStore = SecretStore;
