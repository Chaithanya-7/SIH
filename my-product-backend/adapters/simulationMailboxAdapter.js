class SimulationMailboxAdapter {
    async quarantineMessage(target) {
        console.log(`[SimulationMailboxAdapter] 🧪 SIMULATION MODE: Simulating quarantine for case ${target.case_id} (${target.mailbox})...`);
        return {
            success: true,
            provider_action_id: `sim-act-${Math.floor(100000 + Math.random() * 900000)}`,
            message: 'SIMULATION MODE: Quarantine action simulated cleanly. No actual provider mailbox changes performed.',
            raw_response: { mode: 'SIMULATION', target }
        };
    }

    async restoreMessage(target) {
        console.log(`[SimulationMailboxAdapter] 🧪 SIMULATION MODE: Simulating message restore for case ${target.case_id} (${target.mailbox})...`);
        return {
            success: true,
            provider_action_id: `sim-rst-${Math.floor(100000 + Math.random() * 900000)}`,
            message: 'SIMULATION MODE: Message restore simulated cleanly. No actual provider mailbox changes performed.',
            raw_response: { mode: 'SIMULATION', target }
        };
    }

    async verifyMessageState(target, expectedState) {
        return { verified: true, reason: 'SIMULATION MODE: Verification state confirmed.' };
    }
}

module.exports = new SimulationMailboxAdapter();
