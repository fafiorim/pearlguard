const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const http = require('http');
const https = require('https');
const cookieParser = require('cookie-parser');

// Import authentication middleware
const { 
    basicAuth, 
    sessionAuth, 
    adminAuth, 
    handleLogin,
    isAdminConfigured,
    getUserRole,
    isAdmin 
} = require('./middleware/auth');

const app = express();
const httpPort = process.env.HTTP_PORT || 3000;
const httpsPort = process.env.HTTPS_PORT || 3443;

// System Configuration
let systemConfig = {
    securityMode: process.env.SECURITY_MODE || 'logOnly', // 'prevent', 'logOnly', or 'disabled'
    scanMethod: process.env.SCAN_METHOD || 'buffer', // 'buffer' or 'file'
    scannerUrl: process.env.SCANNER_URL || 'http://localhost:3001', // Scanner service URL
    cloudApiKey: process.env.FSS_API_KEY || '', // TrendAI File Security API Key for local scanner
    externalScannerAddr: process.env.SCANNER_EXTERNAL_ADDR || '', // External gRPC scanner address (e.g., "10.10.21.201:50051")
    externalScannerTLS: process.env.SCANNER_USE_TLS === 'true', // Use TLS for external scanner
    digestEnabled: process.env.DIGEST_ENABLED !== 'false', // true or false (default: true)
    pmlEnabled: process.env.PML_ENABLED === 'true', // Predictive Machine Learning (default: false)
    spnFeedbackEnabled: process.env.SPN_FEEDBACK_ENABLED === 'true', // SPN Feedback (default: false)
    verboseEnabled: process.env.VERBOSE_ENABLED === 'true', // Verbose scan result (default: false)
    activeContentEnabled: process.env.ACTIVE_CONTENT_ENABLED === 'true', // Active content detection (default: false)
};

// Store scan results in memory
let scanResults = [];

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: './uploads',
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage: storage });

// Trust proxy - needed for running behind load balancer
app.set('trust proxy', 1);

// Add cookie parser middleware
app.use(cookieParser());

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'pearlguard-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Will be set dynamically based on protocol
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true,
        sameSite: 'lax'
    },
    name: 'pearlguard.sid', // Custom session cookie name
    proxy: true // Trust the reverse proxy
}));

// Middleware to handle secure cookies behind proxy
app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        req.session.cookie.secure = true;
    }
    next();
});

// Combined auth middleware
const combinedAuth = (req, res, next) => {
    // Check for Basic Auth header
    const authHeader = req.headers.authorization;
    if (authHeader) {
        return basicAuth(req, res, next);
    }
    // If no Basic Auth, check session
    if (req.session && req.session.user) {
        req.user = req.session.user;
        return next();
    }
    // If neither, redirect to login
    res.redirect('/login');
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Store scan result
const storeScanResult = (result) => {
    scanResults.unshift(result);
    if (scanResults.length > 100) {
        scanResults = scanResults.slice(0, 100);
    }
};

// API Endpoints - Move to /api prefix
app.post('/api/upload', (req, res, next) => {
    // Run basic auth first
    basicAuth(req, res, () => {
        // After auth passes, run multer
        upload.array('file')(req, res, async (err) => {
            if (err) {
                return res.status(400).json({ error: 'File upload error' });
            }

            try {
                if (!req.files || req.files.length === 0) {
                    return res.status(400).json({ error: 'No files uploaded' });
                }

                const responses = [];
                
                // Process each file
                for (const file of req.files) {
                    const filePath = path.resolve('./uploads', file.filename);

                    try {
                        // Skip scanning if security mode is disabled
                        if (systemConfig.securityMode === 'disabled') {
                            const scanRecord = {
                                filename: file.originalname,
                                size: file.size,
                                mimetype: file.mimetype,
                                isSafe: null,  // Set to null for not scanned
                                scanId: `SCAN_DISABLED_${Date.now()}`,
                                tags: ['scan_disabled'],
                                timestamp: new Date(),
                                securityMode: systemConfig.securityMode,
                                action: 'Uploaded without scanning',
                                fileStatus: 'Saved',
                                uploadedBy: req.user.username,
                                scannerSource: systemConfig.externalScannerAddr ? `External\n${systemConfig.externalScannerAddr}` : 'SaaS SDK'
                            };
                            
                            storeScanResult(scanRecord);
                            responses.push({ 
                                file: file.originalname,
                                status: 'success',
                                message: 'File uploaded successfully (scanning disabled)',
                                scanResult: {
                                    isSafe: null,
                                    message: 'Scanning disabled'
                                }
                            });
                            continue;
                        }
                        
                        // Prepare scan request based on method
                        let scanRequest;
                        if (systemConfig.scanMethod === 'file') {
                            // For file method, send only the file path
                            scanRequest = axios.post(`${systemConfig.scannerUrl}/scan`, '', {
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-Filename': file.originalname,
                                    'X-Scan-Method': 'file',
                                    'X-File-Path': filePath,
                                    'X-Digest-Enabled': systemConfig.digestEnabled.toString(),
                                    'X-PML-Enabled': systemConfig.pmlEnabled.toString(),
                                    'X-SPN-Feedback-Enabled': systemConfig.spnFeedbackEnabled.toString(),
                                    'X-Verbose-Enabled': systemConfig.verboseEnabled.toString(),
                                    'X-Active-Content-Enabled': systemConfig.activeContentEnabled.toString()
                                }
                            });
                        } else {
                            // For buffer method, read and send the file data
                            const fileData = fs.readFileSync(filePath);
                            scanRequest = axios.post(`${systemConfig.scannerUrl}/scan`, fileData, {
                                headers: {
                                    'Content-Type': 'application/octet-stream',
                                    'X-Filename': file.originalname,
                                    'X-Scan-Method': 'buffer',
                                    'X-File-Path': filePath,
                                    'X-Digest-Enabled': systemConfig.digestEnabled.toString(),
                                    'X-PML-Enabled': systemConfig.pmlEnabled.toString(),
                                    'X-SPN-Feedback-Enabled': systemConfig.spnFeedbackEnabled.toString(),
                                    'X-Verbose-Enabled': systemConfig.verboseEnabled.toString(),
                                    'X-Active-Content-Enabled': systemConfig.activeContentEnabled.toString()
                                }
                            });
                        }
                        
                        try {
                            const scanResponse = await scanRequest;

                            // Use the isSafe field from the scanner response (already properly determined by scanner.go)
                            const isMalwareFound = !scanResponse.data.isSafe;
                            
                            // Parse the detailed scan result for storage
                            const scanResult = JSON.parse(scanResponse.data.message);
                            
                            // Store scan result
                            const scanRecord = {
                                filename: file.originalname,
                                size: file.size,
                                mimetype: file.mimetype,
                                isSafe: scanResponse.data.isSafe,
                                scanId: scanResponse.data.scanId,
                                tags: scanResponse.data.tags || [],
                                timestamp: new Date(),
                                securityMode: systemConfig.securityMode,
                                action: isMalwareFound ? 
                                    (systemConfig.securityMode === 'prevent' ? 'Malware detected and blocked' : 'Malware detected and logged') :
                                    'Scanned and verified safe',
                                fileStatus: isMalwareFound && systemConfig.securityMode === 'prevent' ? 'Deleted' : 'Saved',
                                uploadedBy: req.user.username,
                                scanDetails: scanResult,
                                scannerSource: systemConfig.externalScannerAddr ? `External\n${systemConfig.externalScannerAddr}` : 'SaaS SDK'
                            };
                            
                            if (isMalwareFound) {
                                // Handle malware based on security mode
                                if (systemConfig.securityMode === 'prevent') {
                                    fs.unlinkSync(filePath);
                                    storeScanResult(scanRecord);
                                    responses.push({
                                        file: file.originalname,
                                        status: 'error',
                                        error: 'Malware detected - Upload prevented',
                                        details: scanResponse.data.message,
                                        scanId: scanResponse.data.scanId
                                    });
                                } else {
                                    // Log Only mode - keep file but mark as unsafe
                                    storeScanResult(scanRecord);
                                    responses.push({
                                        file: file.originalname,
                                        status: 'warning',
                                        message: 'File uploaded but marked as unsafe',
                                        warning: 'Malware detected',
                                        scanResult: scanResponse.data
                                    });
                                }
                            } else {
                                // Safe file handling
                                storeScanResult(scanRecord);
                                responses.push({
                                    file: file.originalname,
                                    status: 'success',
                                    message: 'File uploaded and scanned successfully',
                                    scanResult: scanResponse.data
                                });
                            }

                        } catch (scanError) {
                            // Delete file on scan error
                            fs.unlinkSync(filePath);
                            console.error('Scan error:', scanError);
                            responses.push({
                                file: file.originalname,
                                status: 'error',
                                error: 'File scan failed',
                                details: scanError.message
                            });
                        }
                    } catch (fileError) {
                        console.error('File processing error:', fileError);
                        if (fs.existsSync(filePath)) {
                            fs.unlinkSync(filePath);
                        }
                        responses.push({
                            file: file.originalname,
                            status: 'error',
                            error: 'File processing failed'
                        });
                    }
                }

                // Send combined response
                res.json({
                    message: 'File upload processing complete',
                    results: responses
                });

            } catch (error) {
                console.error('Upload error:', error);
                res.status(500).json({ error: 'File upload failed' });
            }
        });
    });
});

app.get('/api/files', basicAuth, (req, res) => {
    try {
        fs.readdir('./uploads', (err, files) => {
            if (err) {
                return res.status(500).json({ error: 'Error reading files' });
            }
            const fileList = files.map(filename => {
                const stats = fs.statSync(path.join('./uploads', filename));
                return {
                    name: filename,
                    size: stats.size,
                    created: stats.birthtime,
                    modified: stats.mtime
                };
            });
            res.json(fileList);
        });
    } catch (error) {
        console.error('File listing error:', error);
        res.status(500).json({ error: 'Error listing files' });
    }
});

app.delete('/api/files/:filename', basicAuth, (req, res) => {
    try {
        const filepath = path.join('./uploads', req.params.filename);
        if (!fs.existsSync(filepath)) {
            return res.status(404).json({ error: 'File not found' });
        }
        fs.unlink(filepath, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Error deleting file' });
            }
            scanResults = scanResults.filter(result => result.filename !== req.params.filename);
            res.json({ message: 'File deleted successfully' });
        });
    } catch (error) {
        console.error('File deletion error:', error);
        res.status(500).json({ error: 'Error deleting file' });
    }
});

// Configuration endpoints with combined auth
app.get('/config', combinedAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'configuration.html'));
});

app.get('/api/config', combinedAuth, (req, res) => {
    res.json({
        ...systemConfig,
        isAdmin: isAdmin(req),
        adminConfigured: isAdminConfigured()
    });
});

app.post('/api/config', combinedAuth, adminAuth, async (req, res) => {
    const { securityMode, scanMethod, scannerUrl, cloudApiKey, externalScannerAddr, externalScannerTLS, digestEnabled, pmlEnabled, spnFeedbackEnabled, verboseEnabled, activeContentEnabled } = req.body;
    
    let needsScannerRestart = false;
    
    if (securityMode && ['prevent', 'logOnly', 'disabled'].includes(securityMode)) {
        systemConfig.securityMode = securityMode;
    }
    
    if (scanMethod && ['buffer', 'file'].includes(scanMethod)) {
        systemConfig.scanMethod = scanMethod;
    }
    
    if (scannerUrl && typeof scannerUrl === 'string') {
        // Validate URL format
        try {
            new URL(scannerUrl);
            systemConfig.scannerUrl = scannerUrl.replace(/\/$/, ''); // Remove trailing slash
        } catch (e) {
            return res.status(400).json({ error: 'Invalid scanner URL format' });
        }
    }
    
    // Handle SaaS SDK API Key configuration
    if (typeof cloudApiKey === 'string') {
        if (systemConfig.cloudApiKey !== cloudApiKey) {
            systemConfig.cloudApiKey = cloudApiKey.trim();
            needsScannerRestart = true;
        }
    }
    
    // Handle external scanner configuration
    if (typeof externalScannerAddr === 'string') {
        if (systemConfig.externalScannerAddr !== externalScannerAddr) {
            systemConfig.externalScannerAddr = externalScannerAddr.trim();
            needsScannerRestart = true;
        }
    }
    
    if (typeof externalScannerTLS === 'boolean') {
        if (systemConfig.externalScannerTLS !== externalScannerTLS) {
            systemConfig.externalScannerTLS = externalScannerTLS;
            needsScannerRestart = true;
        }
    }
    
    if (typeof digestEnabled === 'boolean') {
        systemConfig.digestEnabled = digestEnabled;
    }
    
    if (typeof pmlEnabled === 'boolean') {
        systemConfig.pmlEnabled = pmlEnabled;
    }
    
    if (typeof spnFeedbackEnabled === 'boolean') {
        systemConfig.spnFeedbackEnabled = spnFeedbackEnabled;
    }
    
    if (typeof verboseEnabled === 'boolean') {
        systemConfig.verboseEnabled = verboseEnabled;
    }
    
    if (typeof activeContentEnabled === 'boolean') {
        systemConfig.activeContentEnabled = activeContentEnabled;
    }
    
    // If external scanner config changed, restart scanner process
    if (needsScannerRestart) {
        const { spawn } = require('child_process');
        
        // Kill existing scanner process (if any)
        try {
            require('child_process').execSync('pkill -f "./scanner"');
        } catch (e) {
            // Process might not be running
        }
        
        // Start new scanner with updated environment
        const scannerEnv = {
            ...process.env,
            FSS_API_KEY: systemConfig.cloudApiKey,
            SCANNER_EXTERNAL_ADDR: systemConfig.externalScannerAddr,
            SCANNER_USE_TLS: systemConfig.externalScannerTLS.toString()
        };
        
        const scanner = spawn('./scanner', [], {
            env: scannerEnv,
            detached: true,
            stdio: 'ignore'
        });
        scanner.unref();
        
        // Wait a moment for scanner to start
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    res.json({ message: 'Configuration updated', config: systemConfig });
});

// Test external scanner connection
app.post('/api/test-scanner', combinedAuth, adminAuth, async (req, res) => {
    const { externalScannerAddr, externalScannerTLS } = req.body;
    
    if (!externalScannerAddr || typeof externalScannerAddr !== 'string') {
        return res.status(400).json({ 
            success: false, 
            message: 'External scanner address is required' 
        });
    }
    
    // Validate address format (host:port)
    const addrRegex = /^[\w\.-]+:\d+$/;
    if (!addrRegex.test(externalScannerAddr)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid address format. Use host:port (e.g., 10.10.21.201:50051)' 
        });
    }
    
    try {
        // Try to connect to the scanner by making a health check request
        // We'll spawn a temporary scanner process to test the connection
        const { spawn } = require('child_process');
        const testEnv = {
            ...process.env,
            SCANNER_EXTERNAL_ADDR: externalScannerAddr,
            SCANNER_USE_TLS: (externalScannerTLS === true).toString(),
            FSS_API_KEY: '' // Clear API key for external scanner test
        };
        
        // Create a test by checking if we can reach the scanner's health endpoint
        // For gRPC scanners, we'll try to initialize a client
        const testProcess = spawn('./scanner', [], {
            env: testEnv,
            timeout: 5000
        });
        
        let output = '';
        let errorOutput = '';
        
        testProcess.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        testProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });
        
        const testResult = await new Promise((resolve) => {
            const timeout = setTimeout(() => {
                testProcess.kill();
                resolve({ success: false, message: 'Connection timeout after 5 seconds' });
            }, 5000);
            
            testProcess.on('error', (err) => {
                clearTimeout(timeout);
                resolve({ success: false, message: `Connection error: ${err.message}` });
            });
            
            testProcess.on('exit', (code) => {
                clearTimeout(timeout);
                
                // Check if connection was successful by looking at logs
                if (output.includes('Scanner started in External Scanner mode') || 
                    output.includes('Scanner Service Starting')) {
                    resolve({ 
                        success: true, 
                        message: `Successfully connected to external scanner at ${externalScannerAddr}` 
                    });
                } else if (errorOutput.includes('connection refused') || 
                           errorOutput.includes('no such host') ||
                           errorOutput.includes('timeout')) {
                    resolve({ 
                        success: false, 
                        message: `Cannot reach scanner at ${externalScannerAddr}. Check network connectivity.` 
                    });
                } else if (errorOutput) {
                    resolve({ 
                        success: false, 
                        message: `Connection error: ${errorOutput.substring(0, 200)}` 
                    });
                } else {
                    resolve({ 
                        success: true, 
                        message: `Scanner process started successfully for ${externalScannerAddr}` 
                    });
                }
            });
        });
        
        res.json(testResult);
        
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: `Test failed: ${error.message}` 
        });
    }
});

app.get('/api/health', basicAuth, async (req, res) => {
    let scannerStatus = 'unknown';
    let scannerError = null;
    
    // Check if scanner service is accessible
    if (systemConfig.securityMode !== 'disabled') {
        try {
            const scannerResponse = await axios.get(`${systemConfig.scannerUrl}/health`, { timeout: 2000 });
            scannerStatus = scannerResponse.data.status || 'healthy';
        } catch (error) {
            scannerStatus = 'unhealthy';
            scannerError = error.code === 'ECONNREFUSED' ? 'Scanner service not responding' : error.message;
        }
    } else {
        scannerStatus = 'disabled';
    }
    
    const overallStatus = scannerStatus === 'unhealthy' ? 'degraded' : 'healthy';
    
    res.json({
        status: overallStatus,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        securityMode: systemConfig.securityMode,
        services: {
            webServer: 'healthy',
            scanner: {
                status: scannerStatus,
                error: scannerError
            }
        },
        scanResults: {
            total: scanResults.length,
            safe: scanResults.filter(r => r.isSafe === true).length,
            unsafe: scanResults.filter(r => r.isSafe === false).length,
            notScanned: scanResults.filter(r => r.isSafe === null).length
        }
    });
});

app.get('/api/scan-results', basicAuth, (req, res) => {
    res.json(scanResults);
});

app.get('/api/scanner-logs', basicAuth, (req, res) => {
    const fs = require('fs');
    const logPath = path.join(__dirname, 'scanner.log');
    
    fs.readFile(logPath, 'utf8', (err, data) => {
        if (err) {
            return res.status(404).json({ error: 'Scanner logs not found' });
        }
        res.json({ logs: data });
    });
});

// Legacy endpoints for backward compatibility
app.post('/upload', (req, res) => {
    res.redirect(307, '/api/upload'); // 307 preserves the HTTP method
});

app.get('/files', basicAuth, (req, res) => {
    res.redirect('/api/files');
});

app.delete('/files/:filename', basicAuth, (req, res) => {
    res.redirect(307, `/api/files/${req.params.filename}`);
});

app.get('/health', basicAuth, (req, res) => {
    res.redirect('/api/health');
});

// S3 Object Storage API Routes (proxy to scanner service)
app.post('/api/s3/buckets', basicAuth, async (req, res) => {
    try {
        const response = await axios.post('http://localhost:3001/s3/buckets', req.body);
        res.json(response.data);
    } catch (error) {
        console.error('S3 buckets listing failed:', error.message);
        res.status(error.response?.status || 500).send(error.response?.data || error.message);
    }
});

app.post('/api/s3/objects', basicAuth, async (req, res) => {
    try {
        const response = await axios.post('http://localhost:3001/s3/objects', req.body);
        res.json(response.data);
    } catch (error) {
        console.error('S3 objects listing failed:', error.message);
        res.status(error.response?.status || 500).send(error.response?.data || error.message);
    }
});

app.post('/api/s3/scan', basicAuth, async (req, res) => {
    try {
        const response = await axios.post('http://localhost:3001/s3/scan', req.body);
        
        // Parse the scan result to store in scan history
        const scanData = response.data;
        const scanResult = JSON.parse(scanData.scanResult);
        
        // scanResult: 0 indicates clean, non-zero indicates threat
        const isSafe = scanResult.scanResult === 0;
        
        // Store scan result in history
        const scanRecord = {
            filename: `s3://${scanData.bucket}/${scanData.key}`,
            size: scanResult.fileSize || 0,
            mimetype: 'application/octet-stream',
            isSafe: isSafe,
            scanId: scanResult.scanId,
            tags: [...(req.body.tags || ['source:s3', `bucket:${scanData.bucket}`]), 'scan_method=buffer'],
            timestamp: new Date(),
            securityMode: 'logOnly',
            action: isSafe ? 'Scanned and verified safe' : 'Malware detected in S3 object',
            fileStatus: 'S3 Object',
            uploadedBy: req.user.username,
            scanDetails: scanResult,
            scannerSource: systemConfig.externalScannerAddr ? `External\n${systemConfig.externalScannerAddr}` : 'SaaS SDK',
            objectStorage: {
                region: scanData.region,
                bucket: scanData.bucket,
                key: scanData.key
            }
        };
        
        storeScanResult(scanRecord);
        
        res.json(response.data);
    } catch (error) {
        console.error('S3 scan failed:', error.message);
        res.status(error.response?.status || 500).send(error.response?.data || error.message);
    }
});

// Static files and web routes
app.use(express.static('public'));
app.use('/uploads', sessionAuth, express.static('uploads'));

// Web Routes
app.get('/', (req, res) => {
    if (req.session && req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

app.get('/login', (req, res) => {
    if (req.session && req.session.user) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', handleLogin);

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Protected web routes
app.get('/dashboard', sessionAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/object-storage', sessionAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'object-storage.html'));
});

app.get('/health-status', sessionAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'health-status.html'));
});

app.get('/scan-results', sessionAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'scan-results.html'));
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// SSL configuration
let sslOptions = null;
try {
    sslOptions = {
        key: fs.readFileSync(path.join(__dirname, 'certs', 'private-key.pem')),
        cert: fs.readFileSync(path.join(__dirname, 'certs', 'public-cert.pem'))
    };
} catch (error) {
    console.log('SSL certificates not found, HTTPS will not be available');
}

// Create HTTP & HTTPS servers
const httpServer = http.createServer(app);
let httpsServer = null;

if (sslOptions) {
    httpsServer = https.createServer(sslOptions, app);
}

// Start servers
httpServer.listen(httpPort, '0.0.0.0', () => {
    console.log(`FinGuard HTTP server running on port ${httpPort}`);
});

if (httpsServer) {
    httpsServer.listen(httpsPort, '0.0.0.0', () => {
        console.log(`FinGuard HTTPS server running on port ${httpsPort}`);
    });
}
