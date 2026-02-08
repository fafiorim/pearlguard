# PearlGuard - Financial Services Malware Scanner

[![GitHub](https://img.shields.io/badge/github-fafiorim%2Ffinguard-blue)](https://github.com/fafiorim/pearlguard)
[![Version](https://img.shields.io/badge/version-1.1.0-green)](https://github.com/fafiorim/pearlguard)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Powered by](https://img.shields.io/badge/powered%20by-TrendAI%20File%20Security-red)](https://www.trendmicro.com)

**Disclaimer:** This application is designed for demo purposes only. It is not intended for production deployment under any circumstances. Use at your own risk.

PearlGuard is a specialized malware scanner designed for financial institutions, leveraging TrendAI File Security. Built with a focus on compliance and security, it provides comprehensive file scanning capabilities with advanced detection features and detailed audit trails.

## Features

### Core Capabilities
- **Dual scanner modes** - Cloud API or on-premise gRPC scanner (Kubernetes Vision One)
- **Real-time malware scanning** using TrendAI File Security API
- **Web interface** for file management and monitoring
- **RESTful API** with Basic Authentication
- **Configurable security modes** (Prevent/Log Only/Disabled)
- **Enhanced health monitoring** with real-time service validation
- **Scanner logs viewer** accessible from health status page
- **Session-based authentication** with role-based access control
- **Docker containerization** with multi-architecture support
- **HTTPS support** with self-signed certificates

### Advanced Scanner Features (NEW)
- **PML Detection** - Predictive Machine Learning for zero-day threats
- **SPN Feedback** - Smart Protection Network threat intelligence sharing
- **Verbose Results** - Detailed scan metadata with engine versions and timing
- **Active Content Detection** - Identifies PDF scripts and Office macros
- **Scan Method Selection** - Buffer (in-memory) or File (disk-based) scanning
- **File Hash Calculation** - SHA1/SHA256 digests for audit trails
- **Configuration Tags** - Track scanner settings per scan (ml_enabled, spn_feedback, active_content)

### Security & Compliance
- **Dual scan methods** for flexibility and performance optimization
- **Detailed audit logging** with configurable tags
- **File hash tracking** for forensic analysis
- **Active content detection** for Office/PDF document security
- **Malware detection** with proper status reporting (fixed EICAR detection bug)

## Directory Structure
```
finguard/
├── Dockerfile              # Multi-stage container build
├── docker-compose.yml      # Optional Docker Compose setup
├── start.sh               # Container startup script
├── generate-cert.js       # SSL certificate generator
├── scanner.go             # Go-based scanner service with TrendAI SDK
├── server.js              # Express API server
├── package.json           # Node.js dependencies
├── go.mod                 # Go module dependencies
├── go.sum                 # Go dependency checksums
├── k8s/                   # Kubernetes deployment manifests
│   ├── deployment.yaml   # K8s deployment configuration
│   ├── service.yaml      # LoadBalancer service
│   └── configmap.yaml    # Configuration management
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
│   ├── configuration.html # Scanner configuration (admin)
│   ├── styles.css        # Application styling
│   └── script.js         # Client-side JavaScript
└── samples/               # Sample files for testing
    ├── README.md         # Sample file documentation
    ├── safe-file.pdf     # Clean PDF for testing
    └── file_active_content.pdf # PDF with JavaScript
```

## Quick Start

### Building from Source

```bash
# Clone the repository
git clone https://github.com/fafiorim/pearlguard.git
cd finguard

# Install Node.js dependencies (if building locally)
npm install

# Build the Docker image
docker build -t finguard:latest .
```

### Running with Cloud Scanner (Default)

```bash
# Set your TrendAI File Security API key
export FSS_API_KEY=your_api_key_here

# Run the container
docker run -d \
  -p 3000:3000 \
  -p 3443:3443 \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e SECURITY_MODE="logOnly" \
  --name finguard \
  finguard:latest
```

### Running with External Scanner (Kubernetes Vision One)

```bash
# Run with external gRPC scanner (no API key needed)
docker run -d \
  -p 3000:3000 \
  -p 3443:3443 \
  -e SCANNER_EXTERNAL_ADDR=10.10.21.201:50051 \
  -e SCANNER_USE_TLS=false \
  -e SECURITY_MODE="logOnly" \
  --name finguard \
  finguard:latest
```

> **Note**: See [EXTERNAL_SCANNER.md](EXTERNAL_SCANNER.md) for detailed external scanner configuration guide.

### Access the Application

- **HTTP**: http://localhost:3000
- **HTTPS**: https://localhost:3443
- **Health Status**: http://localhost:3000/health-status
- **Configuration**: http://localhost:3000/configuration
- **API Endpoints**: http://localhost:3000/api/* (with Basic Auth)

### Default Credentials
- **Admin**: `admin` / `admin123`
- **User**: `user` / `user123`

## Scanner Configuration

PearlGuard provides granular control over scanner behavior through the configuration page (admin access required).

### Scanner Modes

**Cloud Scanner Mode (Default)**
- Uses TrendAI File Security API
- Requires FSS_API_KEY
- Protocol: HTTP REST API
- Global threat intelligence network

**External Scanner Mode (Optional)**
- Connects to on-premise Vision One File Security
- No API key required
- Protocol: gRPC
- Example: Kubernetes deployment at 10.10.21.201:50051
- Configurable via Web UI or environment variables
- Built-in connection test to verify scanner accessibility

### Scan Methods

**Buffer Scan (Default)**
- Loads file into memory
- Sends data to scanner via network
- Faster for small files
- Higher memory usage

**File Scan**
- Scanner reads directly from disk
- Lower network overhead
- Better for large files
- Requires shared file system access

### Advanced Detection Features

**PML (Predictive Machine Learning)**
- AI-powered detection for unknown threats
- Zero-day malware detection
- Enhanced by Smart Protection Network data
- Configurable per-scan via `ml_enabled` tag

**SPN Feedback (Smart Protection Network)**
- Shares threat intelligence with TrendAI
- Improves global threat detection
- Real-time correlation analysis
- Tracked via `spn_feedback` tag

PearlGuard Results**
- Detailed scan metadata
- Engine versions and pattern updates
- Scan timing and performance metrics
- File type detection details

**Active Content Detection**
- Identifies PDF JavaScript
- Detects Office macros
- Reports potentially risky embedded code
- Returns `activeContentCount` in results
- Tracked via `active_content` tag

**File Hash Calculation**
- SHA1 and SHA256 digest generation
- Essential for audit trails and forensics
- Toggleable to reduce overhead
- Included in scan results when enabled

### Configuration Tags

Each scan includes tags for audit and compliance:
```
app=finguard                    # Application identifier
file_type=.pdf                  # File extension
scan_method=buffer              # Scan method used
ml_enabled=true                 # PML detection status
spn_feedback=true               # SPN sharing status
active_content=true             # Active content detection
malware_name=Eicar_test_file   # Detected threat (if any)
```

## Sample Files

PearlGuard includes sample files in the `samples/` directory for testing scanner features:

- **safe-file.pdf** - Clean PDF file with no threats
- **file_active_content.pdf** - PDF with embedded JavaScript for active content detection testing
- **README.md** - Detailed testing instructions

Upload these samples with different configurations to see how various detection features work.

## Kubernetes Deployment

PearlGuard includes production-ready Kubernetes manifests in the `k8s/` directory.

### Quick Deploy

```bash
# Create secret with your FSS API key
kubectl create secret generic finguard-secrets \
  --from-literal=admin-password=your_admin_pass \
  --from-literal=user-password=your_user_pass \
  --from-literal=fss-api-key=your_fss_api_key

# Deploy ConfigMap
kubectl apply -f k8s/configmap.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Create LoadBalancer service
kubectl apply -f k8s/service.yaml

# Get external IP
kubectl get svc finguard-service
```

### Kubernetes Resources

- **Deployment**: `k8s/deployment.yaml` - Application deployment with health checks
- **Service**: `k8s/service.yaml` - LoadBalancer service exposing port 3000
- **ConfigMap**: `k8s/configmap.yaml` - Application configuration
- **Secret**: `k8s/secret.yaml` - Template for sensitive data

### Kubernetes Features

- Multi-architecture support (AMD64/ARM64)
- Liveness and readiness probes
- ConfigMap-based configuration
- Secret management for credentials
- LoadBalancer service for external access

## Security Modes

PearlGuard supports three security modes:

### Disabled Mode (Default)
- Bypasses malware scanning
- Files are uploaded directly without scanning
- Maintains logging of uploads with clear "Not Scanned" status
- Suitable for trusted environments or testing
- Can be enabled/disabled by administrators only (when admin account is configured)

### Prevent Mode
- Blocks and deletes malicious files immediately
- Notifies users when malware is detected
- Provides highest security level
- Files marked as malicious are not stored

### Log Only Mode
- Allows all file uploads
- Logs and marks malicious files
- Warns users about detected threats
- Useful for testing and monitoring

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
