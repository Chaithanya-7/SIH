class CampaignResponsePlanner {
    generateResponsePlan(campaignRecord, relatedCases = []) {
        if (!campaignRecord || !campaignRecord.campaign_id) {
            return null;
        }

        console.log(`[CampaignResponsePlanner] Generating Campaign Response Plan for ${campaignRecord.campaign_id}...`);

        const affectedCasesCount = relatedCases.length || campaignRecord.case_ids?.length || 0;
        const affectedRecipients = Array.from(new Set(relatedCases.map(c => c.message?.recipient).filter(Boolean)));

        const recommendedActions = [];

        // Destructive action requires human SOC approval
        if (affectedCasesCount > 0) {
            recommendedActions.push({
                action_id: `CMP-ACT-${Math.floor(1000 + Math.random() * 9000)}`,
                action: 'QUARANTINE_RELATED_MESSAGES',
                campaign_id: campaignRecord.campaign_id,
                affected_cases: affectedCasesCount,
                case_ids: campaignRecord.case_ids || [],
                authorization: 'REQUIRE_APPROVAL',
                reason: `Contain ${affectedCasesCount} correlated message(s) belonging to active threat campaign ${campaignRecord.campaign_id}`
            });
        }

        // Informational alert can auto-execute
        if (affectedRecipients.length > 0) {
            recommendedActions.push({
                action_id: `CMP-ACT-${Math.floor(1000 + Math.random() * 9000)}`,
                action: 'ALERT_AFFECTED_RECIPIENTS',
                campaign_id: campaignRecord.campaign_id,
                affected_recipients: affectedRecipients.length,
                recipients: affectedRecipients,
                authorization: 'AUTO_EXECUTE',
                reason: `Notify ${affectedRecipients.length} target recipient(s) of active phishing campaign targeting organization`
            });
        }

        return {
            campaign_id: campaignRecord.campaign_id,
            status: campaignRecord.status || 'ACTIVE',
            association_confidence: campaignRecord.association_confidence,
            affected_cases_count: affectedCasesCount,
            affected_recipients_count: affectedRecipients.length,
            recommended_actions: recommendedActions,
            limitation: 'Campaign response recommendations group related cases but do not automatically execute destructive actions across the cluster without policy authorization.'
        };
    }
}

module.exports = new CampaignResponsePlanner();
