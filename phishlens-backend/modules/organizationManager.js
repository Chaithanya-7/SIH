const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const userManager = require('./userManager');
const { dataFile } = require('./dataPaths');

class OrganizationManager {
    constructor() {
        this.storageFile = dataFile('organizations.json');
        this.organizations = new Map();
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
                list.forEach(org => this.organizations.set(org.id, org));
            }

            console.log(`[OrganizationManager] Loaded ${this.organizations.size} organization(s) from disk.`);
        } catch (e) {
            console.error('[OrganizationManager] Error loading organization storage:', e.message);
        }
    }

    saveStorage() {
        try {
            const list = Array.from(this.organizations.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(list, null, 2), 'utf8');
        } catch (e) {
            console.error('[OrganizationManager] Error saving organization storage:', e.message);
        }
    }

    generateInviteCode() {
        return `INV-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    }

    createOrganization(userId, name, approvedDomain) {
        const user = userManager.getUserById(userId);
        if (!user) throw new Error('User not found.');

        if (!name || name.trim().length < 2) {
            throw new Error('Valid organization name is required.');
        }

        const domain = (approvedDomain || user.email.split('@')[1] || '').trim().toLowerCase();
        const now = new Date().toISOString();

        const org = {
            id: `org_${crypto.randomBytes(8).toString('hex')}`,
            name: name.trim(),
            approved_domain: domain,
            invite_code: this.generateInviteCode(),
            created_by: user.id,
            created_at: now,
            updated_at: now,
            members: [
                { user_id: user.id, role: 'ADMIN', joined_at: now }
            ]
        };

        this.organizations.set(org.id, org);
        this.saveStorage();

        // Assign user to Organization as ADMIN
        user.organization_id = org.id;
        user.role = 'ADMIN';
        userManager.updateUser(user);

        return { organization: org, user };
    }

    joinOrganizationWithInviteCode(userId, inviteCode) {
        const user = userManager.getUserById(userId);
        if (!user) throw new Error('User not found.');

        if (!inviteCode || !inviteCode.trim()) {
            throw new Error('Admin invite code is required to join an organization.');
        }

        const cleanCode = inviteCode.trim().toUpperCase();
        const org = Array.from(this.organizations.values()).find(o => o.invite_code === cleanCode);

        if (!org) {
            throw new Error('Invalid or expired admin invite code.');
        }

        // Domain eligibility check
        const userDomain = user.email.split('@')[1]?.toLowerCase() || '';
        if (org.approved_domain && userDomain !== org.approved_domain.toLowerCase()) {
            throw new Error(`Email domain @${userDomain} is not eligible to join ${org.name} (Requires @${org.approved_domain}).`);
        }

        const now = new Date().toISOString();
        const existingMember = org.members.find(m => m.user_id === user.id);
        if (!existingMember) {
            org.members.push({ user_id: user.id, role: 'EMPLOYEE', joined_at: now });
            org.updated_at = now;
            this.saveStorage();
        }

        // Assign user to Organization as EMPLOYEE
        user.organization_id = org.id;
        user.role = existingMember ? existingMember.role : 'EMPLOYEE';
        userManager.updateUser(user);

        return { organization: org, user };
    }

    getOrganizationById(orgId) {
        return this.organizations.get(orgId) || null;
    }

    rotateInviteCode(orgId, adminUserId) {
        const org = this.organizations.get(orgId);
        if (!org) throw new Error('Organization not found.');

        const adminMember = org.members.find(m => m.user_id === adminUserId && m.role === 'ADMIN');
        if (!adminMember) throw new Error('Only an Organization ADMIN can rotate invite codes.');

        org.invite_code = this.generateInviteCode();
        org.updated_at = new Date().toISOString();
        this.saveStorage();

        return org;
    }
}

module.exports = new OrganizationManager();
