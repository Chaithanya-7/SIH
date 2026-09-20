const axios = require('axios');

class GmailActionAdapter {
    constructor() {
        this.apiBase = 'https://gmail.googleapis.com/gmail/v1/users/me';
        this.quarantineLabelName = 'PhishLens/Quarantine';
        this.suspiciousLabelName = 'PhishLens/Suspicious';
        this.cachedLabelId = null;
        this.labelCache = new Map();
    }

    /**
     * Fetch or create the PhishLens/Quarantine label in Gmail
     */
    async getOrCreateQuarantineLabel(accessToken) {
        const id = await this.getOrCreateLabel(accessToken, this.quarantineLabelName);
        this.cachedLabelId = id;
        return id;
    }

    /**
     * Resolve a PhishLens label by name, creating it the first time.
     *
     * Cached per label name rather than in a single slot, because there is now
     * more than one: containment moves a message under PhishLens/Quarantine,
     * and a recipient warning marks it PhishLens/Suspicious while leaving it in
     * the inbox. One shared cache slot would have handed the warning path the
     * quarantine label's id.
     */
    async getOrCreateLabel(accessToken, labelName) {
        if (this.labelCache.has(labelName)) {
            return this.labelCache.get(labelName);
        }

        try {
            // 1. Fetch user labels
            const listRes = await axios.get(`${this.apiBase}/labels`, {
                headers: { 'Authorization': `Bearer ${accessToken}` },
                timeout: 10000
            });

            const labels = listRes.data.labels || [];
            const existing = labels.find(l => l.name.toLowerCase() === labelName.toLowerCase());

            if (existing) {
                this.labelCache.set(labelName, existing.id);
                return existing.id;
            }

            // 2. Create label if absent
            console.log(`[GmailActionAdapter] Creating Gmail label '${labelName}'...`);
            const createRes = await axios.post(`${this.apiBase}/labels`, {
                name: labelName,
                labelListVisibility: 'labelShow',
                messageListVisibility: 'show'
            }, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            });

            this.labelCache.set(labelName, createRes.data.id);
            return createRes.data.id;
        } catch (error) {
            console.error(`[GmailActionAdapter] Error resolving label '${labelName}':`, error.response?.data || error.message);
            throw new Error(`Gmail label creation/lookup failed for '${labelName}': ${error.response?.data?.error?.message || error.message}`);
        }
    }

    /**
     * Mark a delivered message as suspicious without removing it.
     *
     * This is the honest form of a "warning banner". A mail provider does not
     * let anyone rewrite the body of a message already delivered to somebody's
     * mailbox, so PhishLens does not pretend to inject one. It applies a label
     * the recipient sees beside the message, and leaves the message in the
     * inbox, which is the whole point for mail that is suspicious but not
     * conclusively malicious.
     */
    async markSuspicious(accessToken, providerMessageId) {
        if (!accessToken || !providerMessageId) {
            throw new Error('accessToken and providerMessageId are required to mark a message suspicious.');
        }
        try {
            const labelId = await this.getOrCreateLabel(accessToken, this.suspiciousLabelName);
            await axios.post(`${this.apiBase}/messages/${providerMessageId}/modify`, {
                addLabelIds: [labelId]
            }, {
                headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
                timeout: 15000
            });

            const currentLabelIds = await this.getMessageState(accessToken, providerMessageId);
            if (currentLabelIds.includes(labelId) && currentLabelIds.includes('INBOX')) {
                return {
                    verified: true,
                    labelId,
                    detail: `Gmail confirmed on read-back: '${this.suspiciousLabelName}' applied and the message left in the inbox.`
                };
            }
            return {
                verified: false,
                error: `Gmail read-back did not confirm the warning label. Current labels: ${currentLabelIds.join(', ')}`
            };
        } catch (error) {
            return { verified: false, error: `Gmail warning label failed: ${error.message}` };
        }
    }

    /**
     * Read current message label state directly from Gmail API
     */
    async getMessageState(accessToken, providerMessageId) {
        try {
            const res = await axios.get(`${this.apiBase}/messages/${providerMessageId}?format=minimal`, {
                headers: { 'Authorization': `Bearer ${accessToken}` },
                timeout: 10000
            });
            return res.data.labelIds || [];
        } catch (error) {
            console.error(`[GmailActionAdapter] Error fetching state for message ${providerMessageId}:`, error.response?.data || error.message);
            throw new Error(`Gmail API read-back failed for message ${providerMessageId}: ${error.response?.data?.error?.message || error.message}`);
        }
    }

    /**
     * Reversible Containment Action:
     * Removes INBOX label, applies PhishLens/Quarantine label, reads back state from Gmail API to verify.
     */
    async containMessage(accessToken, providerMessageId) {
        if (!accessToken || !providerMessageId) {
            throw new Error('accessToken and providerMessageId are required for containment.');
        }

        try {
            const labelId = await this.getOrCreateQuarantineLabel(accessToken);

            console.log(`[GmailActionAdapter] Executing Gmail containment for message ${providerMessageId}...`);
            await axios.post(`${this.apiBase}/messages/${providerMessageId}/modify`, {
                removeLabelIds: ['INBOX'],
                addLabelIds: [labelId]
            }, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                timeout: 15000
            });

            // Mandatory Post-Action Read-Back Provider Verification
            const currentLabelIds = await this.getMessageState(accessToken, providerMessageId);
            const inboxRemoved = !currentLabelIds.includes('INBOX');
            const quarantineAdded = currentLabelIds.includes(labelId);

            if (inboxRemoved && quarantineAdded) {
                console.log(`✅ [GmailActionAdapter] Verified Gmail containment for ${providerMessageId}. INBOX: absent | Quarantine Label: present.`);
                return {
                    verified: true,
                    state: 'QUARANTINED',
                    labelId: labelId,
                    currentLabels: currentLabelIds
                };
            } else {
                console.warn(`❌ [GmailActionAdapter] Verification MISMATCH for ${providerMessageId}. Labels:`, currentLabelIds);
                return {
                    verified: false,
                    state: 'ACTION_FAILED',
                    error: `Provider verification mismatch. Current labels: ${currentLabelIds.join(', ')}`
                };
            }
        } catch (error) {
            console.error(`[GmailActionAdapter] Containment failed for ${providerMessageId}:`, error.message);
            return {
                verified: false,
                state: 'ACTION_FAILED',
                error: error.message
            };
        }
    }

    /**
     * Reversible Release Action:
     * Restores INBOX label, removes PhishLens/Quarantine label, reads back state from Gmail API to verify.
     */
    async releaseMessage(accessToken, providerMessageId, quarantineLabelId = null) {
        if (!accessToken || !providerMessageId) {
            throw new Error('accessToken and providerMessageId are required for release.');
        }

        try {
            const labelId = quarantineLabelId || await this.getOrCreateQuarantineLabel(accessToken);

            console.log(`[GmailActionAdapter] Executing Gmail release for message ${providerMessageId}...`);
            await axios.post(`${this.apiBase}/messages/${providerMessageId}/modify`, {
                addLabelIds: ['INBOX'],
                removeLabelIds: [labelId]
            }, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                timeout: 15000
            });

            // Mandatory Post-Action Read-Back Provider Verification
            const currentLabelIds = await this.getMessageState(accessToken, providerMessageId);
            const inboxRestored = currentLabelIds.includes('INBOX');
            const quarantineRemoved = !currentLabelIds.includes(labelId);

            if (inboxRestored && quarantineRemoved) {
                console.log(`✅ [GmailActionAdapter] Verified Gmail release for ${providerMessageId}. INBOX: restored | Quarantine Label: removed.`);
                return {
                    verified: true,
                    state: 'RELEASED',
                    currentLabels: currentLabelIds
                };
            } else {
                console.warn(`❌ [GmailActionAdapter] Verification MISMATCH for release ${providerMessageId}. Labels:`, currentLabelIds);
                return {
                    verified: false,
                    state: 'ACTION_FAILED',
                    error: `Provider release verification mismatch. Current labels: ${currentLabelIds.join(', ')}`
                };
            }
        } catch (error) {
            console.error(`[GmailActionAdapter] Release failed for ${providerMessageId}:`, error.message);
            return {
                verified: false,
                state: 'ACTION_FAILED',
                error: error.message
            };
        }
    }
}

module.exports = new GmailActionAdapter();
