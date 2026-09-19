const axios = require('axios');

class GmailActionAdapter {
    constructor() {
        this.apiBase = 'https://gmail.googleapis.com/gmail/v1/users/me';
        this.quarantineLabelName = 'PhishLens/Quarantine';
        this.cachedLabelId = null;
    }

    /**
     * Fetch or create the PhishLens/Quarantine label in Gmail
     */
    async getOrCreateQuarantineLabel(accessToken) {
        if (this.cachedLabelId) {
            return this.cachedLabelId;
        }

        try {
            // 1. Fetch user labels
            const listRes = await axios.get(`${this.apiBase}/labels`, {
                headers: { 'Authorization': `Bearer ${accessToken}` },
                timeout: 10000
            });

            const labels = listRes.data.labels || [];
            const existing = labels.find(l => l.name.toLowerCase() === this.quarantineLabelName.toLowerCase());

            if (existing) {
                this.cachedLabelId = existing.id;
                return existing.id;
            }

            // 2. Create label if absent
            console.log(`[GmailActionAdapter] Creating Gmail Quarantine label '${this.quarantineLabelName}'...`);
            const createRes = await axios.post(`${this.apiBase}/labels`, {
                name: this.quarantineLabelName,
                labelListVisibility: 'labelShow',
                messageListVisibility: 'show'
            }, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            });

            this.cachedLabelId = createRes.data.id;
            return createRes.data.id;
        } catch (error) {
            console.error('[GmailActionAdapter] Error resolving Quarantine label:', error.response?.data || error.message);
            throw new Error(`Gmail Quarantine label creation/lookup failed: ${error.response?.data?.error?.message || error.message}`);
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
