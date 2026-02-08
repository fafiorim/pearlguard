const net = require('net');
const fs = require('fs');
const path = require('path');

class ClamAVScanner {
    constructor(host = 'localhost', port = 3310) {
        this.host = host;
        this.port = port;
    }

    /**
     * Scan a file using ClamAV
     * @param {string} filePath - Path to the file to scan
     * @returns {Promise<Object>} Scan result
     */
    async scanFile(filePath) {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();
            const absolutePath = path.resolve(filePath);

            client.connect(this.port, this.host, () => {
                // Send SCAN command with file path
                client.write(`SCAN ${absolutePath}\n`);
            });

            let data = '';
            client.on('data', (chunk) => {
                data += chunk.toString();
            });

            client.on('end', () => {
                try {
                    const result = this.parseResponse(data, filePath);
                    resolve(result);
                } catch (error) {
                    reject(error);
                }
            });

            client.on('error', (error) => {
                reject(new Error(`ClamAV connection error: ${error.message}`));
            });
        });
    }

    /**
     * Scan a buffer using ClamAV
     * @param {Buffer} buffer - Buffer to scan
     * @param {string} identifier - File identifier
     * @returns {Promise<Object>} Scan result
     */
    async scanBuffer(buffer, identifier = 'buffer') {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();

            client.connect(this.port, this.host, () => {
                // Send INSTREAM command
                client.write('zINSTREAM\0');
                
                // Send buffer size (4 bytes, network byte order)
                const size = Buffer.alloc(4);
                size.writeUInt32BE(buffer.length, 0);
                client.write(size);
                
                // Send buffer data
                client.write(buffer);
                
                // Send zero-length chunk to indicate end
                const endChunk = Buffer.alloc(4);
                endChunk.writeUInt32BE(0, 0);
                client.write(endChunk);
            });

            let data = '';
            client.on('data', (chunk) => {
                data += chunk.toString();
            });

            client.on('end', () => {
                try {
                    const result = this.parseResponse(data, identifier);
                    resolve(result);
                } catch (error) {
                    reject(error);
                }
            });

            client.on('error', (error) => {
                reject(new Error(`ClamAV connection error: ${error.message}`));
            });
        });
    }

    /**
     * Parse ClamAV response
     * @param {string} response - Raw response from ClamAV
     * @param {string} identifier - File identifier
     * @returns {Object} Parsed result
     */
    parseResponse(response, identifier) {
        const trimmed = response.trim();
        
        // Response format: "stream: OK" or "stream: Eicar-Test-Signature FOUND"
        if (trimmed.includes('OK')) {
            return {
                isSafe: true,
                scanResult: 0,
                fileName: identifier,
                scanId: `${Date.now()}-${path.basename(identifier)}`,
                timestamp: new Date().toISOString(),
                scannerVersion: 'ClamAV',
                foundMalwares: []
            };
        } else if (trimmed.includes('FOUND')) {
            // Extract malware name
            const match = trimmed.match(/:\s*(.+)\s+FOUND/);
            const malwareName = match ? match[1] : 'Unknown';
            
            return {
                isSafe: false,
                scanResult: 1,
                fileName: identifier,
                scanId: `${Date.now()}-${path.basename(identifier)}`,
                timestamp: new Date().toISOString(),
                scannerVersion: 'ClamAV',
                foundMalwares: [{
                    fileName: identifier,
                    malwareName: malwareName
                }]
            };
        } else if (trimmed.includes('ERROR')) {
            throw new Error(`ClamAV scan error: ${trimmed}`);
        } else {
            throw new Error(`Unknown ClamAV response: ${trimmed}`);
        }
    }

    /**
     * Ping ClamAV to check if it's alive
     * @returns {Promise<boolean>} True if ClamAV responds
     */
    async ping() {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();
            
            client.setTimeout(5000);
            
            client.connect(this.port, this.host, () => {
                client.write('zPING\0');
            });

            let data = '';
            client.on('data', (chunk) => {
                data += chunk.toString();
                if (data.includes('PONG')) {
                    client.end();
                    resolve(true);
                }
            });

            client.on('timeout', () => {
                client.destroy();
                reject(new Error('ClamAV ping timeout'));
            });

            client.on('error', (error) => {
                reject(new Error(`ClamAV connection error: ${error.message}`));
            });
        });
    }

    /**
     * Get ClamAV version
     * @returns {Promise<string>} ClamAV version
     */
    async getVersion() {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();

            client.connect(this.port, this.host, () => {
                client.write('zVERSION\0');
            });

            let data = '';
            client.on('data', (chunk) => {
                data += chunk.toString();
            });

            client.on('end', () => {
                resolve(data.trim());
            });

            client.on('error', (error) => {
                reject(new Error(`ClamAV connection error: ${error.message}`));
            });
        });
    }
}

module.exports = ClamAVScanner;
