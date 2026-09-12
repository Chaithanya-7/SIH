/**
 * SecureMail AI Authentication & Authorization Middleware Boundary
 * Validates SecureMail session tokens (sm_sess_...) and populates req.user.
 */

const userManager = require('../modules/userManager');

const requireAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'] || req.headers['x-api-key'] || req.headers['x-session-token'];
    
    if (authHeader) {
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();

        // 1. Try resolving session token via userManager
        const user = userManager.getUserBySessionToken(token);
        if (user) {
            req.user = user;
            return next();
        }

        // 2. Secret API key for dev test suite or daemon
        const expectedKey = process.env.SECUREMAIL_API_KEY || 'securemail_dev_key_2026';
        if (token === expectedKey) {
            req.user = { id: 'dev-admin', email: 'admin@securemail.ai', role: 'ADMIN', organization_id: 'org_dev' };
            return next();
        }
    }

    // Allow local dev requests if NODE_ENV !== 'production' when no header provided
    if (process.env.NODE_ENV !== 'production' && !authHeader) {
        req.user = { id: 'dev-admin', email: 'admin@securemail.ai', role: 'ADMIN', organization_id: 'org_dev' };
        return next();
    }

    return res.status(401).json({ success: false, error: 'Authentication required. Authorization session token missing or expired.' });
};

const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }
        
        const userRole = req.user.role || 'EMPLOYEE';
        if (allowedRoles.includes(userRole) || userRole === 'ADMIN') {
            return next();
        }

        return res.status(403).json({ success: false, error: `Insufficient permissions. Requires role: ${allowedRoles.join(' or ')}` });
    };
};

module.exports = {
    requireAuth,
    requireRole
};
