class SimulationMailboxAdapter {
    async quarantineMessage(target) {
        console.log(`[SimulationMailboxAdapter] 🧪 SIMULATION MODE: Simulating quarantine for case ${target.case_id} (${target.mailbox})...`);
        return {
            success: true,
            status: 'SIMULATED',
            provider_action_id: `sim-act-${Math.floor(100000 + Math.random() * 900000)}`,
            message: 'SIMULATION MODE: Action simulated cleanly. No actual provider mailbox changes performed.',
            raw_response: { mode: 'SIMULATION', target }
        };
    }

    async restoreMessage(target) {
        console.log(`[SimulationMailboxAdapter] 🧪 SIMULATION MODE: Simulating message restore for case ${target.case_id} (${target.mailbox})...`);
        return {
            success: true,
            status: 'SIMULATED',
            provider_action_id: `sim-rst-${Math.floor(100000 + Math.random() * 900000)}`,
            message: 'SIMULATION MODE: Message restore simulated cleanly. No actual provider mailbox changes performed.',
            raw_response: { mode: 'SIMULATION', target }
        };
    }

    async verifyMessageState(target, expectedState) {
        return { verified: false, status: 'SIMULATED', reason: 'SIMULATION MODE: No live provider mailbox changes performed.' };
    }
}

module.exports = new SimulationMailboxAdapter();
