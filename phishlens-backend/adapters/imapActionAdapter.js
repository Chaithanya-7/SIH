const Imap = require('imap');
const imapAdapter = require('./imapAdapter');

/**
 * Containment for mail that reached PhishLens over IMAP.
 *
 * Remediation used to be Gmail-only, which meant a message polled from an IMAP
 * mailbox could be analysed, scored, correlated and reported on, and then not
 * acted upon at all. A tool that watches several sources but can only act on
 * one of them has a gap exactly where an operator would least expect it.
 *
 * Containment here is a move into a dedicated folder, not a delete. The
 * message stays recoverable, which is what makes an automated decision
 * acceptable in the first place.
 */

const QUARANTINE_BOX = process.env.IMAP_QUARANTINE_FOLDER || 'PhishLens Quarantine';

class ImapActionAdapter {
    constructor() {
        this.quarantineBox = QUARANTINE_BOX;
    }

    /**
     * A short-lived connection of its own. The poller's connection is driven by
     * its own cycle, and borrowing it would mean a containment action could
     * interleave with a fetch and reopen the mailbox underneath it.
     */
    connect() {
        return new Promise((resolve, reject) => {
            const config = imapAdapter.config;
            if (!config.user || !config.password) {
                return reject(new Error('IMAP credentials are not configured, so IMAP containment cannot be performed.'));
            }
            const connection = new Imap(config);
            const onError = (err) => reject(new Error(`IMAP connection failed: ${err.message}`));
            connection.once('ready', () => {
                connection.removeListener('error', onError);
                resolve(connection);
            });
            connection.once('error', onError);
            connection.connect();
        });
    }

    openBox(connection, name, readOnly = false) {
        return new Promise((resolve, reject) => {
            connection.openBox(name, readOnly, (err, box) => (err ? reject(err) : resolve(box)));
        });
    }

    /** Creating a folder that already exists is not an error worth failing on. */
    ensureBox(connection, name) {
        return new Promise((resolve) => {
            connection.addBox(name, () => resolve());
        });
    }

    search(connection, criteria) {
        return new Promise((resolve, reject) => {
            connection.search(criteria, (err, uids) => (err ? reject(err) : resolve(uids || [])));
        });
    }

    move(connection, uid, destination) {
        return new Promise((resolve, reject) => {
            connection.move(String(uid), destination, (err) => (err ? reject(err) : resolve()));
        });
    }

    end(connection) {
        try { connection.end(); } catch (e) { /* the connection is being discarded anyway */ }
    }

    /**
     * Verification cannot follow the UID.
     *
     * A moved message is a new message in the destination folder with a new
     * UID, so the UID we moved is not a handle we can check afterwards. The
     * RFC 5322 Message-ID is the identifier that survives the move, so that is
     * what the read-back searches for. Without one there is nothing stable to
     * confirm against, and the action is reported as unverified rather than
     * assumed to have worked.
     */
    async confirmPresence(connection, box, rfcMessageId) {
        if (!rfcMessageId) return null;
        await this.openBox(connection, box, true);
        const hits = await this.search(connection, [['HEADER', 'MESSAGE-ID', rfcMessageId]]);
        return hits.length > 0;
    }

    async quarantineMessage(target) {
        const rfcMessageId = target.rfc_message_id || null;
        const uid = target.uid || target.message_id;
        let connection;

        try {
            connection = await this.connect();
            await this.ensureBox(connection, this.quarantineBox);
            await this.openBox(connection, target.folder || 'INBOX');

            console.log(`[ImapActionAdapter] Moving UID ${uid} from ${target.folder || 'INBOX'} to '${this.quarantineBox}'...`);
            await this.move(connection, uid, this.quarantineBox);

            const inQuarantine = await this.confirmPresence(connection, this.quarantineBox, rfcMessageId);
            const stillInInbox = await this.confirmPresence(connection, target.folder || 'INBOX', rfcMessageId);

            if (inQuarantine === null) {
                return {
                    verified: false,
                    error: 'The move was issued, but the message carries no Message-ID, so PhishLens cannot confirm where it ended up. Reporting it as contained would be a guess.'
                };
            }

            if (inQuarantine && !stillInInbox) {
                return {
                    verified: true,
                    folder: this.quarantineBox,
                    detail: `IMAP confirmed on read-back: present in '${this.quarantineBox}', absent from the inbox.`
                };
            }

            return {
                verified: false,
                error: `IMAP read-back did not confirm the move (in quarantine: ${inQuarantine}, still in inbox: ${stillInInbox}).`
            };
        } catch (e) {
            return { verified: false, error: `IMAP containment failed: ${e.message}` };
        } finally {
            if (connection) this.end(connection);
        }
    }

    /**
     * Flag a message as suspicious in place, using an IMAP keyword.
     *
     * IMAP has no notion of a label the way Gmail does, but a keyword set on
     * the message is shown by most clients and, importantly, survives being
     * read. The message is not moved: mail that is suspicious rather than
     * conclusively malicious should still reach the person it was sent to.
     */
    async markSuspicious(target) {
        const rfcMessageId = target.rfc_message_id || null;
        const uid = target.uid || target.message_id;
        let connection;

        try {
            connection = await this.connect();
            await this.openBox(connection, target.folder || 'INBOX');

            await new Promise((resolve, reject) => {
                connection.addKeywords(String(uid), ['PhishLensSuspicious'], (err) => (err ? reject(err) : resolve()));
            });

            const stillPresent = await this.confirmPresence(connection, target.folder || 'INBOX', rfcMessageId);
            if (stillPresent === false) {
                return { verified: false, error: 'The message is no longer in the inbox, so the warning keyword could not be confirmed on it.' };
            }

            return {
                verified: true,
                folder: target.folder || 'INBOX',
                detail: 'IMAP keyword PhishLensSuspicious set; the message was left in the inbox.'
            };
        } catch (e) {
            return { verified: false, error: `IMAP warning keyword failed: ${e.message}` };
        } finally {
            if (connection) this.end(connection);
        }
    }

    async releaseMessage(target) {
        const rfcMessageId = target.rfc_message_id || null;
        const inbox = target.folder || 'INBOX';
        let connection;

        if (!rfcMessageId) {
            return {
                verified: false,
                error: 'Release over IMAP needs the Message-ID to locate the message in the quarantine folder, and this case does not carry one.'
            };
        }

        try {
            connection = await this.connect();
            await this.openBox(connection, this.quarantineBox);

            const hits = await this.search(connection, [['HEADER', 'MESSAGE-ID', rfcMessageId]]);
            if (hits.length === 0) {
                return { verified: false, error: `The message is not in '${this.quarantineBox}', so there is nothing to release from it.` };
            }

            await this.move(connection, hits[0], inbox);

            const backInInbox = await this.confirmPresence(connection, inbox, rfcMessageId);
            const stillQuarantined = await this.confirmPresence(connection, this.quarantineBox, rfcMessageId);

            if (backInInbox && !stillQuarantined) {
                return {
                    verified: true,
                    folder: inbox,
                    detail: `IMAP confirmed on read-back: restored to '${inbox}', absent from '${this.quarantineBox}'.`
                };
            }

            return {
                verified: false,
                error: `IMAP read-back did not confirm the release (in inbox: ${backInInbox}, still quarantined: ${stillQuarantined}).`
            };
        } catch (e) {
            return { verified: false, error: `IMAP release failed: ${e.message}` };
        } finally {
            if (connection) this.end(connection);
        }
    }
}

module.exports = new ImapActionAdapter();
