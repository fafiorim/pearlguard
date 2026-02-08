# PearlGuard - Financial Services Malware Scanner

[![GitHub](https://img.shields.io/badge/github-fafiorim%2Ffinguard-blue)](https://github.com/fafiorim/pearlguard)
[![Version](https://img.shields.io/badge/version-1.0.12-green)](https://github.com/fafiorim/pearlguard)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Powered by](https://img.shields.io/badge/powered%20by-ClamAV-red)](https://www.clamav.net)

**Disclaimer:** This application is designed for demo purposes only. It is not intended for production deployment under any circumstances. Use at your own risk.

PearlGuard is a specialized malware scanner designed for financial institutions, leveraging ClamAV for open-source virus detection. Built with a focus on compliance and security, it provides comprehensive file scanning capabilities with detailed audit trails and AWS S3 integration.

## Features

### Core Capabilities
- **ClamAV Integration** - Open-source antivirus scanner with real-time updates
- **Real-time malware scanning** with comprehensive virus signature database
- **AWS S3 Integration** - Scan objects directly from S3 buckets
- **Web interface** for file management and monitoring
- **RESTful API** with Basic Authentication
- **Comprehensive scanner logs** with detailed scan metadata
- **Enhanced health monitoring** with real-time service validation
- **Scanner logs viewer** accessible from health status page
- **Session-based authentication** with role-based access control
- **Kubernetes deployment** with multi-architecture support (AMD64/ARM64)
- **Docker containerization** with optimized builds

### S3 Object Storage Scanner (NEW)
- **Direct S3 Scanning** - Scan files directly from AWS S3 buckets
- **Bucket Browser** - Navigate and explore S3 buckets and objects
- **Multi-Object Selection** - Select and scan multiple files simultaneously
- **Folder Operations** - Select entire folders or buckets for batch scanning
- **Region Support** - Configurable AWS regions for global deployments
- **Custom Endpoints** - Support for S3-compatible storage solutions
- **Detailed Timing** - Performance breakdown (download, buffer, scan)
- **Scan History** - Track all S3 scans with metadata and results

### Scanner Features
- **Buffer-based scanning** - In-memory scanning for optimal performance
- **Detailed scan metadata** - File info, timing, malware details, security context
- **Comprehensive logging** - 8-section verbose logs with emojis for easy reading
- **EICAR detection** - Verified malware detection with test files
- **Virus signature updates** - Automatic ClamAV database updates
- **Multiple file formats** - Support for all common file types

### Security & Compliance
- **Detailed audit logging** with comprehensive scan metadata
- **Security context tracking** - Client IP, user agent, authentication details
- **Malware detection** with proper status reporting and threat identification
- **File statistics** - Size, MIME type, timestamps for compliance
- **Scan duration tracking** - Performance monitoring and optimization

## Directory Structure
```
pearlguard/
├── Dockerfile              # Multi-stage container build
├── docker-compose.yml      # Docker Compose with ClamAV service
├── start.sh               # Container startup script
├── clamav-scanner.js      # ClamAV scanner client library
├── server.js              # Express API server with S3 integration
├── package.json           # Node.js dependencies (AWS SDK, Express)
├── k8s/                   # Kubernetes deployment manifests
│   ├── namespace.yaml    # PearlGuard namespace
│   ├── webapp-deployment.yaml   # Webapp deployment (v1.0.12)
│   ├── clamav-deployment.yaml   # ClamAV service deployment
│   └── configmap.yaml    # Configuration management
├── clamav/                # ClamAV custom configuration
│   ├── Dockerfile        # Custom ClamAV image
│   └── clamd.conf        # ClamAV daemon configuration
├── middleware/            # Application middleware
│   └── auth.js           # Authentication & authorization
├── public/                # Web interface (static files)
│   ├── components/       # Reusable UI components
│   │   └── nav.html     # Navigation component
│   ├── index.html        # Welcome/landing page
│   ├── login.html        # Authentication page
│   ├── dashboard.html    # File upload & management
│   ├── scan-results.html # Scan history with filtering
│   ├── health-status.html # System health dashboard
│   ├── object-storage.html # S3 object storage scanner (NEW)
│   ├── configuration.html # Scanner configuration (admin)
│   ├── styles.css        # Application styling
│   └── script.js         # Client-side JavaScript
└── uploads/               # Temporary upload directory
```

## Quick Start

### Prerequisites
- Docker and Docker Buildx (for multi-architecture builds)
- Kubernetes cluster (for K8s deployment)
- AWS credentials (for S3 scanning feature)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/fafiorim/pearlguard.git
cd pearlguard

# Install Node.js dependencies
npm install

# Build multi-architecture Docker images
docker buildx build --platform linux/amd64,linux/arm64 \
  -t fafiorim/pearlguard-webapp:v1.0.12 --push .

# Build ClamAV service (optional custom build)
cd clamav
docker buildx build --platform linux/amd64,linux/arm64 \
  -t fafiorim/pearlguard-clamav:v1.0.2 --push .
```

### Running with Docker Compose

```bash
# Start both webapp and ClamAV services
docker-compose up -d

# Access the application
open http://localhost:3000
```

### Kubernetes Deployment

```bash
# Apply all Kubernetes manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/clamav-deployment.yaml
kubectl apply -f k8s/webapp-deployment.yaml

# Check deployment status
kubectl get pods -n pearlguard

# Get service endpoint
kubectl get svc -n pearlguard
```

### Access the Application

- **HTTP**: http://localhost:3000 (or your LoadBalancer IP)
- **Health Status**: http://localhost:3000/health-status
- **Scanner Logs**: http://localhost:3000/api/scanner-logs
- **S3 Object Storage**: http://localhost:3000/object-storage.html
- **Configuration**: http://localhost:3000/configuration (admin only)

### Default Credentials
- **Admin**: `admin` / `admin123`
- **User**: `user` / `user123`

## AWS S3 Integration

PearlGuard includes comprehensive S3 object scanning capabilities.

### S3 Scanner Features

**Direct Object Scanning**
- Scan files directly from S3 without downloading locally
- Support for all AWS regions
- Custom endpoint support for S3-compatible services
- Secure credential handling with validation

**Bucket Navigation**
- Browse all accessible S3 buckets
- Navigate folder structures within buckets
- View object metadata (size, last modified, ETag)
- Breadcrumb navigation for easy traversal

**Batch Operations**
- Select multiple objects for scanning
- Select entire folders recursively
- Select entire buckets
- Progress tracking for multi-object scans

**Performance Optimization**
- Detailed timing breakdown (download/buffer/scan)
- In-memory scanning for optimal speed
- Parallel processing support
- Network latency monitoring

### Using S3 Scanner

1. Navigate to **Object Storage** page
2. Enter AWS credentials:
   - Access Key ID
   - Secret Access Key
   - Region (default: us-east-1)
   - Custom Endpoint (optional)
3. Click **Connect & Load Buckets**
4. Browse buckets and select objects
5. Click **Scan Selected** to start scanning

### S3 Scan Results

Each scan provides:
- Clean/Malware status
- Object path (s3://bucket/key)
- File size
- Scan ID
- Duration breakdown
- Malware names (if detected)

All S3 scans are logged in scan history with `source:s3` tag.

## Scanner Configuration

PearlGuard uses ClamAV for virus detection with comprehensive logging.

## Scanner Configuration

PearlGuard uses ClamAV for virus detection with comprehensive logging.

### ClamAV Scanner

**Official ClamAV Image**
- Uses official `clamav/clamav:latest` Docker image
- Automatic virus database updates via freshclam
- TCP connection on port 3310
- INSTREAM protocol for buffer scanning

**Detection Features**
- Comprehensive virus signature database
- Daily signature updates
- EICAR test file detection verified
- All major file format support

### Scanner Logs

PearlGuard provides detailed scanner logs with 8 comprehensive sections:

1. **📊 SCAN STATUS** - Overall result, warnings, errors
2. **📄 FILE INFORMATION** - Name, size, MIME type, scan ID
3. **🔒 SECURITY CONTEXT** - User, IP, authentication, user agent
4. **🔍 SCANNER DETAILS** - ClamAV host/port, scan duration
5. **🦠 MALWARE DETAILS** - Threat names, risk level (if detected)
6. **🏷️ TAGS** - Tracking tags (source, bucket, region, etc.)
7. **📅 FILE TIMESTAMPS** - Upload and scan times
8. **🔬 RAW SCAN DATA** - Full scan response for debugging

### Configuration Options

**ClamAV Detection Features**
- Detect Potentially Unwanted Applications (PUA)
- Alert on Office Macros
- Alert on Encrypted Files
- Structured Data Detection (SSN, Credit Cards)

**Log Levels**
- Verbose logging enabled by default
- Log clean files option
- Extended detection information
- Scan timing and performance metrics

## Kubernetes Deployment

PearlGuard includes production-ready Kubernetes manifests optimized for the pearlguard namespace.

### Architecture

**Webapp Service**
- Deployment: `pearlguard-webapp`
- Image: `fafiorim/pearlguard-webapp:v1.0.12`
- Replicas: 1 (configurable)
- Port: 3000
- Multi-architecture: AMD64/ARM64

**ClamAV Service**
- Deployment: `clamav`
- Image: `clamav/clamav:latest` (official)
- Port: 3310
- Automatic virus DB updates

**LoadBalancer Service**
- Service: `pearlguard-service`
- Type: LoadBalancer
- External Port: 80 → Internal Port: 3000

### Quick Deploy

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Deploy ConfigMap
kubectl apply -f k8s/configmap.yaml

# Deploy ClamAV scanner
kubectl apply -f k8s/clamav-deployment.yaml

# Deploy webapp
kubectl apply -f k8s/webapp-deployment.yaml

# Get service endpoint
kubectl get svc pearlguard-service -n pearlguard
# Example output: EXTERNAL-IP: 10.10.21.202
```

### Kubernetes Resources

- **namespace.yaml** - PearlGuard namespace isolation
- **webapp-deployment.yaml** - Webapp deployment with health checks and resource limits
- **clamav-deployment.yaml** - ClamAV service deployment
- **configmap.yaml** - Environment configuration (ClamAV host, ports, admin credentials)

### Deployment Features

- Multi-architecture support (AMD64/ARM64)
- Resource requests and limits configured
- Health probes for high availability
- ConfigMap-based configuration
- Single replica for consistency
- LoadBalancer for external access

### Monitoring

```bash
# Check pod status
kubectl get pods -n pearlguard

# View webapp logs
kubectl logs deployment/pearlguard-webapp -n pearlguard

# View ClamAV logs
kubectl exec deployment/clamav -n pearlguard -- tail -50 /var/log/clamav/clamd.log

# Check scanner logs via API
curl http://10.10.21.202/api/scanner-logs
```

## API Endpoints

PearlGuard provides a comprehensive RESTful API with Basic Authentication.

### File Operations
- `POST /api/upload` - Upload and scan files
- `GET /api/scan-results` - Retrieve scan history
- `GET /api/scanner-logs` - Get detailed scanner logs with 8 sections

### S3 Object Storage
- `POST /api/s3/buckets` - List S3 buckets (requires AWS credentials)
- `POST /api/s3/objects` - List objects in a bucket
- `POST /api/s3/scan` - Scan an S3 object

### System
- `GET /api/health` - System health check
- `GET /api/clamav-logs` - ClamAV service logs information

### Authentication
All API endpoints require Basic Authentication:
```bash
curl -u admin:admin123 http://localhost:3000/api/scanner-logs
```

### S3 API Example

```bash
# List buckets
curl -u admin:admin123 -X POST http://localhost:3000/api/s3/buckets \
  -H "Content-Type: application/json" \
  -d '{
    "region": "us-east-1",
    "accessKeyId": "YOUR_ACCESS_KEY",
    "secretAccessKey": "YOUR_SECRET_KEY"
  }'

# Scan an object
curl -u admin:admin123 -X POST http://localhost:3000/api/s3/scan \
  -H "Content-Type: application/json" \
  -d '{
    "region": "us-east-1",
    "bucket": "my-bucket",
    "key": "path/to/file.pdf",
    "accessKeyId": "YOUR_ACCESS_KEY",
    "secretAccessKey": "YOUR_SECRET_KEY"
  }'
```

## Testing

### EICAR Test File

Test malware detection with the EICAR test file:

```bash
# Download EICAR test file
wget https://secure.eicar.org/eicar.com

# Upload to PearlGuard
curl -u admin:admin123 -F "file=@eicar.com" http://localhost:3000/api/upload

# Expected result: Malware detected - Eicar-Signature
```

### S3 Testing

1. Upload test files to S3 (including EICAR for malware testing)
2. Navigate to Object Storage page
3. Connect with AWS credentials
4. Select and scan objects
5. Verify results in scan history

## Performance

Typical scan times for S3 objects (<1MB):
- **S3 Download**: 90-110ms (90-95% of total time)
- **Buffer Conversion**: 0-1ms (<1% of total time)
- **ClamAV Scan**: 3-14ms (3-11% of total time)
- **Total**: 98-127ms

Network latency to AWS is the primary factor affecting scan time.

## Authentication

PearlGuard supports two authentication methods:

### Web Interface Authentication
- Session-based authentication
- Login through web interface at `/login`
- Configurable user credentials via environment variables
- Optional admin account for configuration management

### API Authentication
- Basic Authentication for all API endpoints
- Supports both user and admin credentials
- Works with standard API tools and curl commands
- Same credentials as web interface

### Default Credentials
- User Account (Required):
  - Configured via USER_USERNAME and USER_PASSWORD
  - Can upload and manage files
  - Cannot modify system configuration
- Admin Account (Optional):
  - Configured via ADMIN_USERNAME and ADMIN_PASSWORD
  - Full access to all features
  - Can modify system configuration
  - If not configured, configuration changes are disabled

## API Reference

### Endpoints

#### Upload File
```bash
# Upload with user account
curl -X POST http://localhost:3000/api/upload \
  -u "user:your_password" \
  -F "file=@/path/to/your/file.txt"

# Upload with admin account (if configured)
curl -X POST http://localhost:3000/api/upload \
  -u "admin:admin_password" \
  -F "file=@/path/to/your/file.txt"

# Example Response (Safe File)
{
    "message": "File uploaded and scanned successfully",
    "results": [{
        "file": "example.txt",
        "status": "success",
        "message": "File uploaded and scanned successfully",
        "scanResult": {
            "isSafe": true
        }
    }]
}

# Example Response (Disabled Mode)
{
    "message": "File upload processing complete",
    "results": [{
        "file": "example.txt",
        "status": "success",
        "message": "File uploaded successfully (scanning disabled)",
        "scanResult": {
            "isSafe": null,
            "message": "Scanning disabled"
        }
    }]
}
```

#### Get Configuration
```bash
# Access with user account (view only)
curl http://localhost:3000/api/config -u "user:your_password"

# Access with admin account (if configured)
curl http://localhost:3000/api/config -u "admin:admin_password"
```

#### Update Configuration (Admin Only)
```bash
# Only works if admin account is configured
curl -X POST http://localhost:3000/api/config \
  -u "admin:admin_password" \
  -H "Content-Type: application/json" \
  -d '{"securityMode": "prevent"}'
```

#### List Files
```bash
curl http://localhost:3000/api/files -u "user:your_password"
```

#### Get Scan Results
```bash
curl http://localhost:3000/api/scan-results -u "user:your_password"
```

#### Get System Health
```bash
curl http://localhost:3000/api/health -u "user:your_password"
```

#### Get Scanner Logs
```bash
curl http://localhost:3000/api/scanner-logs -u "admin:admin_password"
```

#### Delete File
```bash
curl -X DELETE http://localhost:3000/api/files/filename.txt -u "user:your_password"
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| FSS_API_KEY | TrendAI File Security API Key | Required | Yes |
| FSS_API_ENDPOINT | FSS API Endpoint | antimalware.us-1.cloudone.trendmicro.com:443 | No |
| FSS_CUSTOM_TAGS | Custom tags for scans | (empty) | No |
| FSS_REGION | TrendAI File Security region | us-1 | No |
| SESSION_SECRET | Secret key for session encryption | finguard-secret-key-change-in-production | No |
| USER_USERNAME | Regular user username | user | No |
| USER_PASSWORD | Regular user password | user123 | No |
| ADMIN_USERNAME | Admin username | admin | No |
| ADMIN_PASSWORD | Admin password | admin123 | No |
| SECURITY_MODE | Default security mode (prevent/logOnly/disabled) | disabled | No |
| SCANNER_EXTERNAL_ADDR | External gRPC scanner address | (empty) | No |
| SCANNER_USE_TLS | Use TLS for external scanner | false | No |

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 3000 | HTTP | Web interface and API |
| 3443 | HTTPS | Secure web interface (self-signed cert) |
| 3001 | HTTP | Internal scanner service (not exposed) |

## Web Interface

### Dashboard
- File upload with real-time scanning
- File listing and management
- Delete functionality
- Clear scan status indicators
- Supports drag-and-drop file upload

### Scan Results
- View scan history
- Filter by safe/unsafe/unscanned files
- Detailed scan information
- Clear status badges for each scan state
- Real-time updates

### Health Status
- **Enhanced health monitoring with real-time service validation**
- **Scanner service connectivity checks**
- **Three-state health reporting** (healthy, degraded, unhealthy)
- **Scanner logs viewer** - Click "Total Scans" to view detailed logs
- Scan statistics by category (safe, unsafe, not scanned)
- Security mode status
- System uptime tracking
- Error reporting with detailed messages

### Configuration
- Security mode management
- System settings
- Real-time updates
- Role-based access control
- Disabled when admin account is not configured

## Volumes and Persistence

Mount volumes for persistent storage:
```bash
docker run -d \
  -p 3000:3000 \
  -v /path/on/host:/app/uploads \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e USER_USERNAME="user" \
  -e USER_PASSWORD="your_password" \
  -e SECURITY_MODE="prevent" \
  --name finguard \
  finguard:latest
```

## Version Information

### Latest Release: v1.1.0

**What's New:**
- 🐛 **Fixed S3 scanner result parsing** - Clean files no longer incorrectly flagged as malicious with verbose mode
- 📚 **Improved test documentation** - Clarified that test scripts require running container
- ✨ **Enhanced result detection** - Handles both verbose and standard scan result structures

**Bug Fixes:**
- Fixed S3 Object Storage scanner incorrectly identifying clean files as malicious when verbose or active content detection enabled
- Enhanced scan result parsing to properly handle `result.atse.malwareCount` (verbose) and `scanResult` (standard) structures
- Removed confusing DEBUG output from S3 scan results display

**Documentation:**
- Clarified test script prerequisites in README.md
- Added note that test-quick.sh and test-all.sh test already-running containers

**Technical Details:**
- TrendAI SDK: tm-v1-fs-golang-sdk v1.7.0
- Go: 1.24.12
- Node.js: Compatible with latest LTS
- Multi-architecture: AMD64, ARM64

**Previous Versions:**
- v1.0.0 - Initial production release with advanced scanner features
- See [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) for detailed changelog

## Troubleshooting

### Common Issues

#### Authentication Issues
- Verify correct credentials are being used
- Check if credentials contain special characters
- Ensure proper Basic Auth encoding for API calls
- Verify admin account is configured if attempting admin operations

#### Scanner Issues
- Verify FSS_API_KEY is set correctly
- Check scanner logs: `docker logs finguard | grep scanner`
- Verify both ports (3000 and 3001) are accessible
- Check if security mode is not disabled

#### Configuration Issues
- Verify admin account is configured if trying to change settings
- Check if user has appropriate permissions
- Verify security mode settings

#### Upload Issues
- Check file permissions
- Verify scanner status
- Check upload size limits
- Verify correct credentials for API uploads

View logs:
```bash
# View all container logs
docker logs finguard
docker logs -f finguard  # Follow mode

# View scanner service logs
docker exec finguard cat /var/log/scanner.log
docker exec finguard tail -f /var/log/scanner.log

# View S3 scanner logs (if using Object Storage)
docker exec finguard cat /var/log/s3-scanner.log
docker exec finguard tail -f /var/log/s3-scanner.log
```

## Testing

PearlGuard includes comprehensive test scripts to validate functionality on running instances.

### Quick Smoke Test (5 seconds)

```bash
./test-quick.sh
```

Tests core functionality on a running container:
- ✓ Health endpoint
- ✓ Authentication
- ✓ EICAR malware detection
- ✓ Scan results API

### Comprehensive Test Suite (30 seconds)

```bash
./test-all.sh
```

Tests all features on a running container:
- ✓ Health checks and service status
- ✓ Authentication (admin & user roles)
- ✓ Scanner configurations (PML, Verbose, Active Content, etc.)
- ✓ Security modes (prevent, logOnly, disabled)
- ✓ EICAR malware detection
- ✓ Safe file scanning (samples/safe-file.pdf)
- ✓ Active content detection (samples/file_active_content.pdf)
- ✓ Scan results API

**Note**: Both `test-quick.sh` and `test-all.sh` test an already-running PearlGuard instance. Make sure the container is running before executing these tests.

### Manual Testing

#### Test with Sample Files

```bash
# Upload safe PDF
curl -X POST http://localhost:3000/api/upload \
  -u 'admin:admin123' \
  -F 'file=@samples/safe-file.pdf'

# Enable active content detection
curl -X POST http://localhost:3000/api/config \
  -u 'admin:admin123' \
  -H 'Content-Type: application/json' \
  -d '{"activeContentEnabled":true}'

# Upload PDF with JavaScript
curl -X POST http://localhost:3000/api/upload \
  -u 'admin:admin123' \
  -F 'file=@samples/file_active_content.pdf'
```

#### Test Malware Detection

```bash
# Download EICAR test file
curl -o eicar.com https://secure.eicar.org/eicar.com

# Upload EICAR (should be detected as malware)
curl -X POST http://localhost:3000/api/upload \
  -u 'admin:admin123' \
  -F 'file=@eicar.com'
```

See [TESTING.md](TESTING.md) for complete test documentation and CI/CD integration examples.

### Test Advanced Features

```bash
# Enable all advanced features
curl -X POST http://localhost:3000/api/config \
  -u 'admin:admin123' \
  -H 'Content-Type: application/json' \
  -d '{
    "securityMode":"logOnly",
    "scanMethod":"buffer",
    "digestEnabled":true,
    "pmlEnabled":true,
    "spnFeedbackEnabled":true,
    "verboseEnabled":true,
    "activeContentEnabled":true
  }'

# Check configuration
curl http://localhost:3000/api/config -u 'admin:admin123'

# Upload a file to see all features in action
curl -X POST http://localhost:3000/api/upload \
  -u 'admin:admin123' \
  -F 'file=@samples/file_active_content.pdf'
```

## Contributing

This is a demo application. For production use cases, please contact TrendAI for enterprise solutions.

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- GitHub Issues: https://github.com/fafiorim/pearlguard/issues
- TrendAI File Security: https://www.trendmicro.com

## Acknowledgments

- Built with TrendAI File Security
- Powered by Go 1.24.12 and Node.js
- Scanner SDK: tm-v1-fs-golang-sdk v1.7.0
