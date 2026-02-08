const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const ClamAVScanner = require('./clamav-scanner');
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

// Initialize ClamAV Scanner
const clamavHost = process.env.CLAMAV_HOST || 'localhost';
const clamavPort = parseInt(process.env.CLAMAV_PORT) || 3310;
const clamavScanner = new ClamAVScanner(clamavHost, clamavPort);

// System Configuration
let systemConfig = {
    securityMode: process.env.SECURITY_MODE || 'logOnly', // 'prevent', 'logOnly', or 'disabled'
    scanMethod: process.env.SCAN_METHOD || 'buffer', // 'buffer' or 'file'
    clamavHost: clamavHost,
    clamavPort: clamavPort,
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
                                scannerSource: 'Scanning Disabled'
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
                        
                        // Scan file using ClamAV
                        let scanResponse;
                        try {
                            if (systemConfig.scanMethod === 'file') {
                                // Scan using file path
                                scanResponse = await clamavScanner.scanFile(filePath);
                            } else {
                                // Scan using buffer
                                const fileData = fs.readFileSync(filePath);
                                scanResponse = await clamavScanner.scanBuffer(fileData, file.originalname);
                            }

                            // Use the isSafe field from the scanner response
                            const isMalwareFound = !scanResponse.isSafe;
                            
                            // Get the detailed scan result
                            const scanResult = {
                                fileName: scanResponse.fileName,
                                scanResult: scanResponse.scanResult,
                                foundMalwares: scanResponse.foundMalwares || []
                            };
                            
                            // Store scan result
                            const scanRecord = {
                                filename: file.originalname,
                                size: file.size,
                                mimetype: file.mimetype,
                                isSafe: scanResponse.isSafe,
                                scanId: scanResponse.scanId,
                                tags: scanResponse.foundMalwares || [],
                                timestamp: new Date(),
                                securityMode: systemConfig.securityMode,
                                action: isMalwareFound ? 
                                    (systemConfig.securityMode === 'prevent' ? 'Malware detected and blocked' : 'Malware detected and logged') :
                                    'Scanned and verified safe',
                                fileStatus: isMalwareFound && systemConfig.securityMode === 'prevent' ? 'Deleted' : 'Saved',
                                uploadedBy: req.user.username,
                                scanDetails: scanResult,
                                scannerSource: `ClamAV\n${systemConfig.clamavHost}:${systemConfig.clamavPort}`
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
                                        details: scanResponse.scanResult,
                                        scanId: scanResponse.scanId
                                    });
                                } else {
                                    // Log Only mode - keep file but mark as unsafe
                                    storeScanResult(scanRecord);
                                    responses.push({
                                        file: file.originalname,
                                        status: 'warning',
                                        message: 'File uploaded but marked as unsafe',
                                        warning: 'Malware detected',
                                        scanResult: scanResponse
                                    });
                                }
                            } else {
                                // Safe file handling
                                storeScanResult(scanRecord);
                                responses.push({
                                    file: file.originalname,
                                    status: 'success',
                                    message: 'File uploaded and scanned successfully',
                                    scanResult: scanResponse
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
    const { securityMode, scanMethod } = req.body;
    
    if (securityMode && ['prevent', 'logOnly', 'disabled'].includes(securityMode)) {
        systemConfig.securityMode = securityMode;
    }
    
    if (scanMethod && ['buffer', 'file'].includes(scanMethod)) {
        systemConfig.scanMethod = scanMethod;
    }
    
    res.json({ 
        success: true, 
        message: 'Configuration updated successfully',
        config: systemConfig
    });
});

// Test ClamAV scanner connection
app.post('/api/test-scanner', combinedAuth, adminAuth, async (req, res) => {
    try {
        // Test ClamAV connection with ping
        const pingResult = await clamavScanner.ping();
        
        if (pingResult) {
            // Get version info
            const version = await clamavScanner.getVersion();
            
            res.json({
                success: true,
                message: 'ClamAV scanner is accessible',
                scanner: {
                    host: systemConfig.clamavHost,
                    port: systemConfig.clamavPort,
                    version: version
                }
            });
        } else {
            res.json({
                success: false,
                message: 'ClamAV scanner did not respond'
            });
        }
    } catch (error) {
        res.json({
            success: false,
            message: `Connection error: ${error.message}`
        });
    }
});


app.get('/api/health', basicAuth, async (req, res) => {
    let scannerStatus = 'unknown';
    let scannerError = null;
    let scannerVersion = null;
    
    // Check if scanner service is accessible
    if (systemConfig.securityMode !== 'disabled') {
        try {
            const pingResponse = await clamavScanner.ping();
            scannerStatus = pingResponse ? 'healthy' : 'unhealthy';
            
            // Get scanner version if healthy
            if (scannerStatus === 'healthy') {
                scannerVersion = await clamavScanner.getVersion();
            }
        } catch (error) {
            scannerStatus = 'unhealthy';
            scannerError = error.message || 'ClamAV service not responding';
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
                error: scannerError,
                version: scannerVersion,
                host: `${systemConfig.clamavHost}:${systemConfig.clamavPort}`
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
