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
const { S3Client, ListBucketsCommand, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');

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
                        const scanStartTime = Date.now();
                        try {
                            if (systemConfig.scanMethod === 'file') {
                                // Scan using file path
                                scanResponse = await clamavScanner.scanFile(filePath);
                            } else {
                                // Scan using buffer
                                const fileData = fs.readFileSync(filePath);
                                scanResponse = await clamavScanner.scanBuffer(fileData, file.originalname);
                            }
                            const scanDuration = Date.now() - scanStartTime;

                            // Use the isSafe field from the scanner response
                            const isMalwareFound = !scanResponse.isSafe;
                            
                            // Get the detailed scan result
                            const scanResult = {
                                fileName: scanResponse.fileName,
                                scanResult: scanResponse.scanResult,
                                foundMalwares: scanResponse.foundMalwares || [],
                                scannerVersion: scanResponse.scannerVersion,
                                scanTimestamp: scanResponse.timestamp
                            };
                            
                            // Calculate file stats
                            const fileStats = fs.existsSync(filePath) ? fs.statSync(filePath) : null;
                            
                            // Store scan result with ALL available information
                            const scanRecord = {
                                filename: file.originalname,
                                originalFilename: file.filename,  // Server-side filename
                                filePath: filePath,
                                size: file.size,
                                mimetype: file.mimetype,
                                encoding: file.encoding,
                                isSafe: scanResponse.isSafe,
                                scanId: scanResponse.scanId,
                                tags: [
                                    `scan_method=${systemConfig.scanMethod}`,
                                    `security_mode=${systemConfig.securityMode}`,
                                    `file_type=${path.extname(file.originalname)}`
                                ],
                                timestamp: new Date(),
                                scanDuration: scanDuration,  // in milliseconds
                                securityMode: systemConfig.securityMode,
                                scanMethod: systemConfig.scanMethod,
                                action: isMalwareFound ? 
                                    (systemConfig.securityMode === 'prevent' ? 'Malware detected and blocked' : 'Malware detected and logged') :
                                    'Scanned and verified safe',
                                fileStatus: isMalwareFound && systemConfig.securityMode === 'prevent' ? 'Deleted' : 'Saved',
                                uploadedBy: req.user.username,
                                userAgent: req.headers['user-agent'],
                                clientIp: req.ip || req.connection.remoteAddress,
                                scanDetails: scanResult,
                                scannerSource: `ClamAV`,
                                scannerHost: systemConfig.clamavHost,
                                scannerPort: systemConfig.clamavPort,
                                fileStats: fileStats ? {
                                    created: fileStats.birthtime,
                                    modified: fileStats.mtime,
                                    accessed: fileStats.atime
                                } : null
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
    const { 
        securityMode, 
        scanMethod, 
        digestEnabled, 
        detectPUA, 
        alertOLE2Macros, 
        alertEncrypted, 
        structuredDataDetection 
    } = req.body;
    
    if (securityMode && ['prevent', 'logOnly', 'disabled'].includes(securityMode)) {
        systemConfig.securityMode = securityMode;
    }
    
    if (scanMethod && ['buffer', 'file'].includes(scanMethod)) {
        systemConfig.scanMethod = scanMethod;
    }
    
    // Store ClamAV feature flags (note: requires ClamAV restart to apply)
    if (typeof digestEnabled === 'boolean') systemConfig.digestEnabled = digestEnabled;
    if (typeof detectPUA === 'boolean') systemConfig.detectPUA = detectPUA;
    if (typeof alertOLE2Macros === 'boolean') systemConfig.alertOLE2Macros = alertOLE2Macros;
    if (typeof alertEncrypted === 'boolean') systemConfig.alertEncrypted = alertEncrypted;
    if (typeof structuredDataDetection === 'boolean') systemConfig.structuredDataDetection = structuredDataDetection;
    
    res.json({ 
        success: true, 
        message: 'Configuration updated successfully. Note: ClamAV detection features require pod restart to apply.',
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
    // ClamAV logs are in the ClamAV pod, not in this application
    // Return scan results instead which provide better information with ALL available details
    const recentScans = scanResults.slice(0, 50).map(scan => {
        const timestamp = new Date(scan.timestamp).toLocaleString();
        const status = scan.isSafe ? 'CLEAN' : (scan.isSafe === null ? 'NOT_SCANNED' : 'INFECTED');
        const malware = scan.scanDetails?.foundMalwares?.[0]?.malwareName || 'N/A';
        
        // Format file size
        const formatSize = (bytes) => {
            if (!bytes) return 'N/A';
            if (bytes < 1024) return `${bytes}B`;
            if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)}KB`;
            if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)}MB`;
            return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)}GB`;
        };
        
        // Format duration
        const formatDuration = (ms) => {
            if (!ms) return 'N/A';
            if (ms < 1000) return `${ms}ms`;
            return `${(ms / 1000).toFixed(2)}s`;
        };
        
        // Build comprehensive log entry with ALL available information
        let logEntry = `[${timestamp}] ${scan.filename}`;
        logEntry += `\n${'─'.repeat(80)}`;
        
        // Scan Status Section
        logEntry += `\n📊 SCAN STATUS`;
        logEntry += `\n  Status: ${status}`;
        if (!scan.isSafe && scan.isSafe !== null) {
            logEntry += ` ⚠️`;
            logEntry += `\n  ⚠️  Threat Detected: ${malware}`;
        }
        logEntry += `\n  Scan ID: ${scan.scanId}`;
        logEntry += `\n  Scan Duration: ${formatDuration(scan.scanDuration)}`;
        logEntry += `\n  Scan Method: ${scan.scanMethod || 'buffer'}`;
        
        // File Information Section
        logEntry += `\n\n📄 FILE INFORMATION`;
        logEntry += `\n  File Name: ${scan.filename}`;
        if (scan.originalFilename) {
            logEntry += `\n  Server Filename: ${scan.originalFilename}`;
        }
        logEntry += `\n  File Size: ${formatSize(scan.size)}`;
        logEntry += `\n  MIME Type: ${scan.mimetype || 'unknown'}`;
        if (scan.encoding) {
            logEntry += `\n  Encoding: ${scan.encoding}`;
        }
        logEntry += `\n  File Extension: ${path.extname(scan.filename) || 'none'}`;
        logEntry += `\n  File Status: ${scan.fileStatus || 'N/A'}`;
        if (scan.filePath) {
            logEntry += `\n  File Path: ${scan.filePath}`;
        }
        
        // Security & Action Section
        logEntry += `\n\n🔒 SECURITY CONTEXT`;
        logEntry += `\n  Security Mode: ${scan.securityMode || 'logOnly'}`;
        logEntry += `\n  Action Taken: ${scan.action || 'N/A'}`;
        logEntry += `\n  Uploaded By: ${scan.uploadedBy || 'unknown'}`;
        if (scan.clientIp) {
            logEntry += `\n  Client IP: ${scan.clientIp}`;
        }
        if (scan.userAgent) {
            logEntry += `\n  User Agent: ${scan.userAgent.substring(0, 80)}${scan.userAgent.length > 80 ? '...' : ''}`;
        }
        
        // Scanner Information Section
        logEntry += `\n\n🔍 SCANNER DETAILS`;
        logEntry += `\n  Scanner: ${scan.scannerSource || 'ClamAV'}`;
        logEntry += `\n  Scanner Host: ${scan.scannerHost || 'N/A'}`;
        logEntry += `\n  Scanner Port: ${scan.scannerPort || 'N/A'}`;
        if (scan.scanDetails?.scannerVersion) {
            logEntry += `\n  Scanner Version: ${scan.scanDetails.scannerVersion}`;
        }
        if (scan.scanDetails?.scanTimestamp) {
            logEntry += `\n  Scanner Timestamp: ${scan.scanDetails.scanTimestamp}`;
        }
        
        // Malware Details Section (if infected)
        if (!scan.isSafe && scan.isSafe !== null && scan.scanDetails?.foundMalwares?.length > 0) {
            logEntry += `\n\n🦠 MALWARE DETAILS`;
            scan.scanDetails.foundMalwares.forEach((malware, idx) => {
                logEntry += `\n  [${idx + 1}] Malware Name: ${malware.malwareName}`;
                if (malware.fileName) {
                    logEntry += `\n      File: ${malware.fileName}`;
                }
            });
        }
        
        // Tags Section
        if (scan.tags && scan.tags.length > 0) {
            logEntry += `\n\n🏷️  TAGS`;
            logEntry += `\n  ${scan.tags.join(', ')}`;
        }
        
        // File Stats Section (if available)
        if (scan.fileStats) {
            logEntry += `\n\n📅 FILE TIMESTAMPS`;
            if (scan.fileStats.created) {
                logEntry += `\n  Created: ${new Date(scan.fileStats.created).toLocaleString()}`;
            }
            if (scan.fileStats.modified) {
                logEntry += `\n  Modified: ${new Date(scan.fileStats.modified).toLocaleString()}`;
            }
            if (scan.fileStats.accessed) {
                logEntry += `\n  Accessed: ${new Date(scan.fileStats.accessed).toLocaleString()}`;
            }
        }
        
        // Raw Scan Result (for debugging)
        if (scan.scanDetails?.scanResult !== undefined) {
            logEntry += `\n\n🔬 RAW SCAN DATA`;
            logEntry += `\n  Scan Result Code: ${scan.scanDetails.scanResult}`;
        }
        
        return logEntry;
    }).join('\n\n' + '═'.repeat(80) + '\n\n');
    
    const logs = recentScans || 'No scan activity yet';
    res.json({ logs });
});

// Get ClamAV daemon logs directly
app.get('/api/clamav-logs', basicAuth, async (req, res) => {
    try {
        const lines = parseInt(req.query.lines) || 100;
        
        // Try to read ClamAV logs from the ClamAV container via HTTP request
        // Since we can't directly access the ClamAV container filesystem,
        // we'll return a message indicating logs should be checked directly
        const logMessage = `
ClamAV Daemon Logs
==================

To view detailed ClamAV daemon logs, use:
  kubectl exec -n pearlguard deployment/clamav -- tail -n ${lines} /var/log/clamav/clamd.log

The ClamAV logs contain:
- Signature database loading information
- Per-scan detection results
- Virus/malware signatures found
- System resource limits
- Self-check status

Current ClamAV Configuration:
- LogVerbose: ${systemConfig.clamavLogVerbose || 'Not configured'}
- LogClean: ${systemConfig.clamavLogClean || 'Not configured'}
- ExtendedDetectionInfo: ${systemConfig.clamavExtendedInfo || 'Not configured'}

Note: Direct ClamAV log access requires pod exec permissions.
Application-level scan logs are available at /api/scanner-logs
        `.trim();
        
        res.json({ logs: logMessage });
    } catch (error) {
        console.error('Error fetching ClamAV logs:', error);
        res.status(500).json({ error: 'Failed to fetch ClamAV logs' });
    }
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

// S3 Object Storage API Routes
app.post('/api/s3/buckets', basicAuth, async (req, res) => {
    try {
        const { region, accessKeyId, secretAccessKey, endpoint } = req.body;
        
        console.log('🔵 S3 Buckets Request:', {
            hasRegion: !!region,
            hasAccessKeyId: !!accessKeyId,
            hasSecretAccessKey: !!secretAccessKey,
            hasEndpoint: !!endpoint,
            accessKeyIdType: typeof accessKeyId,
            secretAccessKeyType: typeof secretAccessKey,
            accessKeyIdLength: accessKeyId?.length,
            secretAccessKeyLength: secretAccessKey?.length,
            regionValue: region,
            endpointValue: endpoint
        });
        
        // Validate credentials
        if (!accessKeyId || !secretAccessKey) {
            console.log('❌ S3 Credentials validation failed:', { accessKeyId: !!accessKeyId, secretAccessKey: !!secretAccessKey });
            return res.status(400).json({ error: 'Access Key ID and Secret Access Key are required' });
        }
        
        // Trim whitespace from credentials
        const trimmedAccessKey = accessKeyId.trim();
        const trimmedSecretKey = secretAccessKey.trim();
        
        const s3Config = {
            region: region?.trim() || 'us-east-1',
            credentials: {
                accessKeyId: trimmedAccessKey,
                secretAccessKey: trimmedSecretKey
            }
        };
        
        if (endpoint && endpoint.trim()) {
            s3Config.endpoint = endpoint.trim();
            s3Config.forcePathStyle = true;
        }
        
        console.log('🔵 S3 Config created:', {
            region: s3Config.region,
            hasEndpoint: !!s3Config.endpoint,
            accessKeyIdLength: trimmedAccessKey.length,
            secretAccessKeyLength: trimmedSecretKey.length
        });
        
        const s3Client = new S3Client(s3Config);
        const command = new ListBucketsCommand({});
        console.log('🔵 Sending ListBucketsCommand...');
        const response = await s3Client.send(command);
        console.log('✅ S3 buckets retrieved successfully:', response.Buckets?.length || 0, 'buckets');
        
        res.json({
            buckets: response.Buckets.map(b => ({
                name: b.Name,
                creationDate: b.CreationDate
            }))
        });
    } catch (error) {
        console.error('❌ S3 buckets listing failed:', {
            message: error.message,
            code: error.code,
            statusCode: error.$metadata?.httpStatusCode,
            requestId: error.$metadata?.requestId,
            stack: error.stack
        });
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/s3/objects', basicAuth, async (req, res) => {
    try {
        const { region, accessKeyId, secretAccessKey, endpoint, bucket, prefix } = req.body;
        
        console.log('🟢 S3 Objects Request:', {
            hasRegion: !!region,
            hasAccessKeyId: !!accessKeyId,
            hasSecretAccessKey: !!secretAccessKey,
            hasEndpoint: !!endpoint,
            bucket: bucket,
            prefix: prefix
        });
        
        // Validate credentials
        if (!accessKeyId || !secretAccessKey) {
            console.log('❌ S3 Credentials validation failed');
            return res.status(400).json({ error: 'Access Key ID and Secret Access Key are required' });
        }
        
        if (!bucket) {
            return res.status(400).json({ error: 'Bucket name is required' });
        }
        
        // Trim whitespace from credentials
        const trimmedAccessKey = accessKeyId.trim();
        const trimmedSecretKey = secretAccessKey.trim();
        
        const s3Config = {
            region: region?.trim() || 'us-east-1',
            credentials: {
                accessKeyId: trimmedAccessKey,
                secretAccessKey: trimmedSecretKey
            }
        };
        
        if (endpoint && endpoint.trim()) {
            s3Config.endpoint = endpoint.trim();
            s3Config.forcePathStyle = true;
        }
        
        const s3Client = new S3Client(s3Config);
        const command = new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: prefix || ''
        });
        const response = await s3Client.send(command);
        
        res.json({
            objects: (response.Contents || []).map(obj => ({
                key: obj.Key,
                size: obj.Size,
                lastModified: obj.LastModified,
                etag: obj.ETag
            }))
        });
    } catch (error) {
        console.error('❌ S3 objects listing failed:', {
            message: error.message,
            code: error.code,
            statusCode: error.$metadata?.httpStatusCode,
            stack: error.stack
        });
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/s3/scan', basicAuth, async (req, res) => {
    try {
        const { region, accessKeyId, secretAccessKey, endpoint, bucket, key } = req.body;
        
        console.log('🟡 S3 Scan Request:', {
            hasRegion: !!region,
            hasAccessKeyId: !!accessKeyId,
            hasSecretAccessKey: !!secretAccessKey,
            hasEndpoint: !!endpoint,
            bucket: bucket,
            key: key
        });
        
        // Validate credentials
        if (!accessKeyId || !secretAccessKey) {
            console.log('❌ S3 Scan credentials validation failed');
            return res.status(400).json({ error: 'Access Key ID and Secret Access Key are required' });
        }
        
        if (!bucket || !key) {
            return res.status(400).json({ error: 'Bucket and key are required' });
        }
        
        // Trim whitespace from credentials
        const trimmedAccessKey = accessKeyId.trim();
        const trimmedSecretKey = secretAccessKey.trim();
        
        const s3Config = {
            region: region?.trim() || 'us-east-1',
            credentials: {
                accessKeyId: trimmedAccessKey,
                secretAccessKey: trimmedSecretKey
            }
        };
        
        if (endpoint && endpoint.trim()) {
            s3Config.endpoint = endpoint.trim();
            s3Config.forcePathStyle = true;
        }
        
        const s3Client = new S3Client(s3Config);
        
        const overallStartTime = Date.now();
        
        // Download file from S3
        console.log('🟡 Downloading from S3:', { bucket, key });
        const downloadStartTime = Date.now();
        const getCommand = new GetObjectCommand({
            Bucket: bucket,
            Key: key
        });
        const s3Response = await s3Client.send(getCommand);
        const downloadDuration = Date.now() - downloadStartTime;
        console.log('✅ S3 download completed:', { duration: `${downloadDuration}ms`, contentType: s3Response.ContentType });
        
        // Convert stream to buffer (optimized)
        console.log('🟡 Converting stream to buffer...');
        const bufferStartTime = Date.now();
        const chunks = [];
        for await (const chunk of s3Response.Body) {
            chunks.push(chunk);
        }
        const fileBuffer = Buffer.concat(chunks);
        const bufferDuration = Date.now() - bufferStartTime;
        console.log('✅ Buffer conversion completed:', { size: fileBuffer.length, duration: `${bufferDuration}ms` });
        
        // Scan with ClamAV
        console.log('🟡 Scanning with ClamAV...');
        const scanStartTime = Date.now();
        const scanResponse = await clamavScanner.scanBuffer(fileBuffer, key);
        const scanDuration = Date.now() - scanStartTime;
        const overallDuration = Date.now() - overallStartTime;
        console.log('✅ ClamAV scan completed:', { 
            duration: `${scanDuration}ms`, 
            isSafe: scanResponse.isSafe,
            overallDuration: `${overallDuration}ms`,
            breakdown: {
                download: `${downloadDuration}ms (${((downloadDuration/overallDuration)*100).toFixed(1)}%)`,
                buffer: `${bufferDuration}ms (${((bufferDuration/overallDuration)*100).toFixed(1)}%)`,
                scan: `${scanDuration}ms (${((scanDuration/overallDuration)*100).toFixed(1)}%)`
            }
        });
        
        const isMalwareFound = !scanResponse.isSafe;
        
        // Store scan result
        const scanRecord = {
            filename: `s3://${bucket}/${key}`,
            size: fileBuffer.length,
            mimetype: s3Response.ContentType || 'application/octet-stream',
            isSafe: scanResponse.isSafe,
            scanId: scanResponse.scanId,
            tags: [
                'source:s3',
                `bucket:${bucket}`,
                `region:${region}`,
                'scan_method=buffer'
            ],
            timestamp: new Date(),
            scanDuration: overallDuration,
            timingBreakdown: {
                s3Download: downloadDuration,
                bufferConversion: bufferDuration,
                clamavScan: scanDuration,
                total: overallDuration
            },
            securityMode: 'logOnly',
            scanMethod: 'buffer',
            action: isMalwareFound ? 'Malware detected in S3 object' : 'S3 object scanned and verified safe',
            fileStatus: 'S3 Object',
            uploadedBy: req.user.username,
            clientIp: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent'],
            scanDetails: {
                fileName: scanResponse.fileName,
                scanResult: scanResponse.scanResult,
                foundMalwares: scanResponse.foundMalwares || [],
                scannerVersion: scanResponse.scannerVersion,
                scanTimestamp: scanResponse.timestamp
            },
            scannerSource: 'ClamAV',
            scannerHost: systemConfig.clamavHost,
            scannerPort: systemConfig.clamavPort,
            objectStorage: {
                region: region,
                bucket: bucket,
                key: key,
                etag: s3Response.ETag,
                lastModified: s3Response.LastModified
            }
        };
        
        storeScanResult(scanRecord);
        
        res.json({
            isSafe: scanResponse.isSafe,
            scanId: scanResponse.scanId,
            fileName: key,
            fileSize: fileBuffer.length,
            scanDuration: overallDuration,
            timingBreakdown: {
                s3Download: `${downloadDuration}ms`,
                bufferConversion: `${bufferDuration}ms`,
                clamavScan: `${scanDuration}ms`,
                total: `${overallDuration}ms`
            },
            malwareDetected: isMalwareFound,
            foundMalwares: scanResponse.foundMalwares,
            bucket: bucket,
            key: key,
            region: region
        });
    } catch (error) {
        console.error('S3 scan failed:', error.message);
        res.status(500).json({ error: error.message, details: error.stack });
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
