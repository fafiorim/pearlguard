// middleware/auth.js

// Get environment variables with defaults
const userUsername = process.env.USER_USERNAME || 'user';
const userPassword = process.env.USER_PASSWORD || 'user123';
const adminUsername = process.env.ADMIN_USERNAME || '';  // Empty default for optional admin
const adminPassword = process.env.ADMIN_PASSWORD || '';  // Empty default for optional admin

/**
 * Basic Authentication middleware for API endpoints
 */
const basicAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        try {
            const base64Credentials = authHeader.split(' ')[1];
            // Add UTF-8 decoder to properly handle special characters
            const decoder = new TextDecoder('utf-8');
            let credentials;
            try {
                // First try regular base64 decode
                credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
            } catch (e) {
                // If that fails, try decoding the UTF-8 bytes
                const bytes = Buffer.from(base64Credentials, 'base64');
                credentials = decoder.decode(bytes);
            }

            // Split credentials and clean any quotes or special characters
            let [username, password] = credentials.split(':');
            
            // Clean up credentials - remove quotes and whitespace
            username = username.replace(/['"]/g, '').trim();
            password = password.replace(/['"]/g, '').trim();
            
            console.log('Attempting auth for user:', username); // Debug log

            // Always check user credentials
            if (username === userUsername && password === userPassword) {
                console.log('User authentication successful'); // Debug log
                req.user = {
                    username,
                    role: 'user'
                };
                return next();
            }

            // Only check admin credentials if they are configured
            if (adminUsername && adminPassword && 
                username === adminUsername && password === adminPassword) {
                console.log('Admin authentication successful'); // Debug log
                req.user = {
                    username,
                    role: 'admin'
                };
                return next();
            }

            console.log('Authentication failed for user:', username); // Debug log
        } catch (error) {
            console.error('Auth parsing error:', error);
        }
    }

    res.setHeader('WWW-Authenticate', 'Basic realm="ByteVault API"');
    res.status(401).json({ error: 'Authentication required' });
};

/**
 * Session authentication middleware for web routes
 */
const sessionAuth = (req, res, next) => {
    if (!req.session || !req.session.user) {
        return res.redirect('/login');
    }
    next();
};

/**
 * Admin authentication middleware
 */
const adminAuth = (req, res, next) => {
    // First check if admin is configured
    if (!adminUsername || !adminPassword) {
        return res.status(403).json({ 
            error: 'Administrator account is not configured. System configuration cannot be modified.' 
        });
    }

    // Then check if user is admin
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Only administrators can modify system configuration' 
        });
    }

    next();
};

/**
 * Handle login requests
 */
const handleLogin = (req, res) => {
    const { username, password } = req.body;
    
    // Remove any quotes that might be in the credentials
    const cleanUsername = username.replace(/['"]/g, '');
    const cleanPassword = password.replace(/['"]/g, '');
    
    // Check user credentials
    if (cleanUsername === userUsername && cleanPassword === userPassword) {
        req.session.user = { 
            username: cleanUsername,
            role: 'user'
        };
        return res.json({ success: true, redirect: '/dashboard' });
    }

    // Only check admin credentials if they are configured
    if (adminUsername && adminPassword && 
        cleanUsername === adminUsername && cleanPassword === adminPassword) {
        req.session.user = { 
            username: cleanUsername,
            role: 'admin'
        };
        return res.json({ success: true, redirect: '/dashboard' });
    }

    res.status(401).json({ error: 'Invalid credentials' });
};

/**
 * Helper function to check if admin account is configured
 */
const isAdminConfigured = () => {
    return Boolean(adminUsername && adminPassword);
};

/**
 * Helper function to get user role
 */
const getUserRole = (req) => {
    if (!req.user) return 'none';
    return req.user.role;
};

/**
 * Helper function to check if user is admin
 */
const isAdmin = (req) => {
    return req.user && 
           req.user.role === 'admin' && 
           isAdminConfigured();
};

/**
 * Helper function to get current auth status
 */
const getAuthStatus = () => {
    return {
        userConfigured: true, // User is always configured
        adminConfigured: isAdminConfigured(),
        userUsername: userUsername,
        adminUsername: adminUsername || 'Not Configured'
    };
};

// Export all authentication related functions
module.exports = {
    basicAuth,
    sessionAuth,
    adminAuth,
    handleLogin,
    isAdminConfigured,
    getUserRole,
    isAdmin,
    getAuthStatus
};
