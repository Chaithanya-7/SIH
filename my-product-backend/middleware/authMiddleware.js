/**
 * PhishLens authentication and authorization middleware boundary.
 * Validates PhishLens session tokens and populates req.user.
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

        // A service key is intended for a controlled ingestion daemon or test suite.
        // Never provide a built-in fallback: a default key turns authentication into
        // an unauthenticated public endpoint as soon as the source is available.
        const expectedKey = process.env.PHISHLENS_API_KEY;
        if (expectedKey && token === expectedKey) {
            req.user = { id: 'service-admin', email: 'admin@phishlens.local', role: 'ADMIN', organization_id: 'org_dev' };
            return next();
        }
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
