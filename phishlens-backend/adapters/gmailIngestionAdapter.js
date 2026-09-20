const axios = require('axios');
const crypto = require('crypto');
const tokenStore = require('../modules/tokenStore');
const mailboxConnectionManager = require('../modules/mailboxConnectionManager');
const dedupStore = require('../modules/dedupStore');
const ingestionRegistry = require('../modules/ingestionRegistry');

class GmailIngestionAdapter {
    constructor() {
        this.clientId = process.env.GOOGLE_CLIENT_ID || '';
        this.clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
        this.redirectUri = process.env.GMAIL_REDIRECT_URI || 'http://localhost:3001/api/auth/gmail/callback';
        this.apiBase = 'https://gmail.googleapis.com/gmail/v1/users';
        this.pipelineHandler = null;
    }

    setPipelineHandler(pipelineHandler) {
        this.pipelineHandler = pipelineHandler;
        this.reportState();
    }

    /**
     * States precisely what is missing before Gmail can be connected, so an
     * operator is told what to do rather than meeting an opaque failure at the
     * OAuth redirect.
     */
    preflight() {
        const missing = [];
        if (!this.clientId) missing.push('GOOGLE_CLIENT_ID');
        if (!this.clientSecret) missing.push('GOOGLE_CLIENT_SECRET');

        const connections = typeof mailboxConnectionManager.getAllConnections === 'function'
            ? mailboxConnectionManager.getAllConnections()
            : [];
        const connected = connections.filter(c => c.status === 'CONNECTED');

        return {
            oauth_app_configured: missing.length === 0,
            missing_environment: missing,
            redirect_uri: this.redirectUri,
            connected_mailboxes: connected.length,
            ready: missing.length === 0 && connected.length > 0,
            next_step: missing.length > 0
                ? `Create an OAuth client in a Google Cloud project, then set ${missing.join(' and ')} plus GMAIL_REDIRECT_URI (currently ${this.redirectUri}).`
                : connected.length === 0
                    ? 'OAuth is configured. Connect a mailbox from the dashboard to begin ingesting mail.'
                    : 'Gmail ingestion is configured and at least one mailbox is connected.',
            limitation: 'Push delivery additionally requires a Google Cloud Pub/Sub topic with a push subscription pointing at /api/webhooks/gmail. Without it, mail is only collected when a sync runs.'
        };
    }

    /** Publishes Gmail's real readiness to the ingestion coverage report. */
    reportState() {
        const state = this.preflight();
        ingestionRegistry.setState('gmail_api', {
            configured: state.oauth_app_configured,
            enabled: state.oauth_app_configured,
            status: state.ready
                ? ingestionRegistry.STATUS.ACTIVE
                : ingestionRegistry.STATUS.NOT_CONFIGURED,
            detail: state.next_step
        });
    }

    getAuthUrl(state = '', promptScope = 'modify') {
        const scopeString = promptScope === 'modify'
            ? 'https://www.googleapis.com/auth/gmail.modify openid email profile'
            : 'https://www.googleapis.com/auth/gmail.readonly openid email profile';

        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: scopeString,
            access_type: 'offline',
            prompt: 'consent',
            state: state
        });
        return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    }

    async exchangeCodeForTokens(code) {
        if (!code) throw new Error('Authorization code is required.');

        try {
            const res = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
                code: code,
                client_id: this.clientId,
                client_secret: this.clientSecret,
                redirect_uri: this.redirectUri,
                grant_type: 'authorization_code'
            }).toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: 10000
            });

            return res.data;
        } catch (error) {
            console.error('[GmailIngestionAdapter] Token exchange error:', error.response?.data?.error || error.message);
            throw new Error(`Gmail OAuth token exchange failed: ${error.response?.data?.error_description || error.message}`);
        }
    }

    async getValidAccessToken(userId) {
        const tokenData = tokenStore.getTokens(userId);
        if (!tokenData) {
            throw new Error('No Gmail OAuth tokens found for user.');
        }

        const now = Date.now();
        // If access token is valid for at least 60 seconds, return it
        if (tokenData.access_token && tokenData.expiry_date && (tokenData.expiry_date - now > 60000)) {
            return tokenData.access_token;
        }

        // Attempt token refresh if refresh_token is present
        if (!tokenData.refresh_token) {
            const connection = mailboxConnectionManager.getConnectionByUser(userId);
            if (connection) {
                mailboxConnectionManager.updateStatus(connection.id, 'AUTH_REQUIRED', 'Refresh token missing. Re-authorization required.');
            }
            throw new Error('Gmail refresh token missing. Re-authorization required.');
        }

        try {
            console.log(`[GmailIngestionAdapter] Refreshing Gmail access token for user ${userId}...`);
            const res = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
                client_id: this.clientId,
                client_secret: this.clientSecret,
                refresh_token: tokenData.refresh_token,
                grant_type: 'refresh_token'
            }).toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: 10000
            });

            const refreshedData = {
                access_token: res.data.access_token,
                refresh_token: tokenData.refresh_token,
                expiry_date: Date.now() + (res.data.expires_in || 3600) * 1000,
                token_type: res.data.token_type || 'Bearer',
                scope: res.data.scope || tokenData.scope
            };

            tokenStore.saveTokens(userId, tokenData.mailbox_email, refreshedData);

            const connection = mailboxConnectionManager.getConnectionByUser(userId);
            if (connection && connection.status !== 'CONNECTED') {
                mailboxConnectionManager.updateStatus(connection.id, 'CONNECTED');
            }

            return refreshedData.access_token;
        } catch (error) {
            console.error('[GmailIngestionAdapter] Access token refresh error:', error.response?.data?.error || error.message);
            const connection = mailboxConnectionManager.getConnectionByUser(userId);
            if (connection) {
                mailboxConnectionManager.updateStatus(connection.id, 'TOKEN_EXPIRED', 'Token refresh failed or was revoked.');
            }
            throw new Error('Gmail access token refresh failed. Mailbox status updated to TOKEN_EXPIRED.');
        }
    }

    hasModifyScope(userId) {
        const tokenData = tokenStore.getTokens(userId);
        if (!tokenData || !tokenData.scope) return false;
        return tokenData.scope.includes('gmail.modify') || tokenData.scope.includes('https://www.googleapis.com/auth/gmail.modify');
    }

    async getValidAccessTokenByMailbox(mailboxEmail) {
        if (!mailboxEmail) throw new Error('Recipient mailbox email is required to resolve OAuth credentials.');
        const tokenData = tokenStore.getTokensByMailbox(mailboxEmail);
        if (!tokenData) {
            throw new Error(`No Gmail OAuth tokens found for recipient mailbox: ${mailboxEmail}`);
        }
        return await this.getValidAccessToken(tokenData.user_id);
    }

    async getGmailProfile(accessToken) {
        try {
            const res = await axios.get(`${this.apiBase}/me/profile`, {
                headers: { 'Authorization': `Bearer ${accessToken}` },
                timeout: 10000
            });
            return res.data;
        } catch (error) {
            console.error('[GmailIngestionAdapter] Get profile error:', error.response?.data || error.message);
            throw new Error(`Failed to fetch Gmail profile: ${error.message}`);
        }
    }

    async fetchRawMessage(accessToken, messageId) {
        try {
            const res = await axios.get(`${this.apiBase}/me/messages/${messageId}?format=raw`, {
                headers: { 'Authorization': `Bearer ${accessToken}` },
                timeout: 15000
            });

            const rawBase64Url = res.data.raw;
            if (!rawBase64Url) throw new Error(`Raw email payload missing for message ID ${messageId}`);

            // Decode base64url to raw UTF-8 string
            const base64 = rawBase64Url.replace(/-/g, '+').replace(/_/g, '/');
            const rawMimeString = Buffer.from(base64, 'base64').toString('utf8');

            return {
                id: res.data.id,
                threadId: res.data.threadId,
                historyId: res.data.historyId,
                rawMimeString: rawMimeString
            };
        } catch (error) {
            console.error(`[GmailIngestionAdapter] Error fetching raw message ${messageId}:`, error.response?.data || error.message);
            throw error;
        }
    }

    async syncGmailHistory(mailboxConnection, pushHistoryId = null) {
        if (!mailboxConnection || !mailboxConnection.user_id) {
            throw new Error('Valid MailboxConnection is required for history sync.');
        }

        const userId = mailboxConnection.user_id;
        const mailboxEmail = mailboxConnection.provider_account;
        const accessToken = await this.getValidAccessToken(userId);

        const startHistoryId = mailboxConnection.history_id || pushHistoryId;
        console.log(`📡 [GmailIngestionAdapter] Syncing Gmail history for ${mailboxEmail} (Start HistoryID: ${startHistoryId || 'LATEST'})...`);

        let newMsgIds = [];
        let latestHistoryId = pushHistoryId || startHistoryId;

        if (startHistoryId) {
            try {
                const historyUrl = `${this.apiBase}/me/history?startHistoryId=${startHistoryId}&historyTypes=messageAdded`;
                const historyRes = await axios.get(historyUrl, {
                    headers: { 'Authorization': `Bearer ${accessToken}` },
                    timeout: 10000
                });

                if (historyRes.data.historyId) {
                    latestHistoryId = historyRes.data.historyId;
                }

                const records = historyRes.data.history || [];
                records.forEach(h => {
                    (h.messagesAdded || []).forEach(m => {
                        if (m.message && m.message.id && !newMsgIds.includes(m.message.id)) {
                            newMsgIds.push(m.message.id);
                        }
                    });
                });

            } catch (error) {
                const status = error.response?.status;
                if (status === 404 || status === 400) {
                    console.warn(`[GmailIngestionAdapter] History ID ${startHistoryId} expired/invalid for ${mailboxEmail}. Performing controlled resynchronization fallback...`);
                    // Controlled resynchronization fallback: query recent messages
                    const listRes = await axios.get(`${this.apiBase}/me/messages?maxResults=10`, {
                        headers: { 'Authorization': `Bearer ${accessToken}` },
                        timeout: 10000
                    });

                    newMsgIds = (listRes.data.messages || []).map(m => m.id);
                } else {
                    throw error;
                }
            }
        } else {
            // Initial sync: fetch latest messages
            const listRes = await axios.get(`${this.apiBase}/me/messages?maxResults=10`, {
                headers: { 'Authorization': `Bearer ${accessToken}` },
                timeout: 10000
            });
            newMsgIds = (listRes.data.messages || []).map(m => m.id);
        }

        console.log(`📬 [GmailIngestionAdapter] Discovered ${newMsgIds.length} Gmail message(s) for ${mailboxEmail}.`);

        let processedCount = 0;
        let lastSuccessfulHistoryId = latestHistoryId;

        for (const msgId of newMsgIds) {
            try {
                // Fetch raw MIME from Gmail API
                const messageData = await this.fetchRawMessage(accessToken, msgId);
                const rawMime = messageData.rawMimeString;

                // Extract RFC Message-ID if present
                const rfcMatch = rawMime.match(/^Message-ID:\s*(<[^>]+>)/mi);
                const rfcMessageId = rfcMatch ? rfcMatch[1] : null;

                // Compute durable deduplication key
                const messageKey = dedupStore.computeMessageKey(rfcMessageId, rawMime, mailboxEmail, msgId);

                // Reserve message key
                const dedupCheck = dedupStore.reserveMessageKey(messageKey, {
                    source: 'GMAIL_PUSH',
                    mailbox: mailboxEmail,
                    provider_message_id: msgId,
                    rfc_message_id: rfcMessageId,
                    raw_sha256: crypto.createHash('sha256').update(rawMime).digest('hex')
                });

                if (dedupCheck.isDuplicate && dedupCheck.isCompleted) {
                    console.log(`[GmailIngestion] Message ${msgId} (${messageKey}) already completed. Skipping.`);
                    continue;
                }

                if (dedupCheck.isDuplicate && dedupCheck.isProcessing) {
                    console.log(`[GmailIngestion] Message ${msgId} (${messageKey}) is already processing. Skipping concurrent execution.`);
                    continue;
                }

                if (this.pipelineHandler) {
                    await this.pipelineHandler(rawMime, 'GMAIL_PUSH', messageKey, {
                        provider: 'GMAIL',
                        provider_account: mailboxEmail,
                        provider_message_id: msgId,
                        mailbox_connection_id: mailboxConnection.connection_id || null,
                        organization_id: mailboxConnection.organization_id || null
                    });
                    processedCount++;
                }

                if (messageData.historyId) {
                    lastSuccessfulHistoryId = messageData.historyId;
                }

            } catch (err) {
                console.error(`❌ [GmailIngestionAdapter] Error processing Gmail message ${msgId}:`, err.message);
                // Pipeline failure does NOT advance history checkpoint past this failed message
            }
        }

        // Update history checkpoint ONLY AFTER discovered messages reach durable processing checkpoint
        if (lastSuccessfulHistoryId) {
            mailboxConnectionManager.updateHistoryCheckpoint(mailboxConnection.id, lastSuccessfulHistoryId);
        }

        return {
            mailbox: mailboxEmail,
            discovered: newMsgIds.length,
            processed: processedCount,
            latestHistoryId: lastSuccessfulHistoryId
        };
    }
}

module.exports = new GmailIngestionAdapter();
