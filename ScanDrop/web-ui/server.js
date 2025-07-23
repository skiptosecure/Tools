const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

// Setup logging
const logFile = '/app/logs/web-ui-debug.log';
function log(message) {
    const timestamp = new Date().toISOString();
    const logMessage = `${timestamp} - ${message}\n`;
    console.log(logMessage.trim());
    fs.appendFileSync(logFile, logMessage);
}

// Ensure log directory exists
fs.mkdirSync('/app/logs', { recursive: true });
log('=== Web UI Starting ===');

// Load SSL certificate
const options = {
  key: fs.readFileSync('/app/ssl/private-key.pem'),
  cert: fs.readFileSync('/app/ssl/certificate.pem')
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.get('/', (req, res) => {
  log('Home page requested');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/analyze', async (req, res) => {
  log('=== ANALYZE REQUEST RECEIVED ===');
 
  try {
    const url = req.body.url;
    log(`Received URL: ${url}`);
    log(`Request headers: ${JSON.stringify(req.headers)}`);
    log(`Request body: ${JSON.stringify(req.body)}`);
   
    if (!url) {
      log('ERROR: No URL provided');
      return res.status(400).send('<html><body><h2>Error: No URL provided</h2></body></html>');
    }
   
    log('Forwarding to file-analyzer...');
   
    const requestBody = `url=${encodeURIComponent(url)}`;
    log(`Request body to send: ${requestBody}`);
   
    const response = await fetch('http://file-analyzer:5000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'SOC-Web-UI/1.0'
      },
      body: requestBody
    });
   
    log(`File-analyzer response status: ${response.status}`);
    log(`File-analyzer response headers: ${JSON.stringify([...response.headers])}`);
   
    const result = await response.text();
    log(`File-analyzer response length: ${result.length} chars`);
    log(`File-analyzer response preview: ${result.substring(0, 200)}...`);
   
    log('Sending result back to browser');
    res.send(result);
   
  } catch (error) {
    log(`ERROR in web-ui: ${error.message}`);
    log(`ERROR stack: ${error.stack}`);
   
    res.status(500).send(`
      <html>
      <body>
        <h2>❌ Web UI Error</h2>
        <p><strong>Error:</strong> ${error.message}</p>
        <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
        <a href="/">← Try Again</a>
        <br><br>
        <details>
          <summary>Debug Info</summary>
          <pre>Check logs: docker exec soc-tool-web-ui-1 cat /app/logs/web-ui-debug.log</pre>
        </details>
      </body>
      </html>
    `);
  }
});

// New files endpoint - proxy to file-analyzer with download links
app.get('/files', async (req, res) => {
  log('Files page requested');
  
  try {
    // Fetch file list from file-analyzer
    const response = await fetch('http://file-analyzer:5000/files');
    
    if (!response.ok) {
      throw new Error(`File-analyzer returned ${response.status}`);
    }
    
    const filesHtml = await response.text();
    
    // Parse the HTML to extract file information (simple approach)
    // For production, you'd want the file-analyzer to return JSON instead
    const fileMatches = filesHtml.match(/<tr><td style='padding: 10px;'>([^<]+)<\/td><td style='padding: 10px;'>([^<]+)<\/td><td style='padding: 10px; font-family: monospace; font-size: 11px;'>([^<]+)<\/td><\/tr>/g);
    
    let fileLinks = '';
    if (fileMatches) {
      fileLinks = fileMatches.map(match => {
        const parts = match.match(/>([^<]+)</g);
        if (parts && parts.length >= 3) {
          const filename = parts[0].slice(1, -1);
          const filesize = parts[1].slice(1, -1);
          const hash = parts[2].slice(1, -1);
          
          return `
            <tr>
              <td style='padding: 15px;'>
                <a href="/download/${encodeURIComponent(filename)}" 
                   style="color: #007bff; text-decoration: none; font-weight: bold;"
                   download="${filename}">
                  📄 ${filename}
                </a>
              </td>
              <td style='padding: 15px;'>${filesize}</td>
              <td style='padding: 15px; font-family: monospace; font-size: 11px;'>${hash}</td>
            </tr>
          `;
        }
        return '';
      }).join('');
    }
    
    // Create enhanced files page with download links
    const enhancedHtml = `
      <html>
      <head>
        <title>SOC Downloaded Files</title>
        <style>
          body { font-family: Arial; max-width: 1200px; margin: 50px auto; padding: 20px; }
          table { width: 100%; border-collapse: collapse; margin: 20px 0; }
          th, td { border: 1px solid #ddd; text-align: left; }
          th { background: #f8f9fa; font-weight: bold; }
          a:hover { text-decoration: underline !important; }
          .nav-buttons { margin: 30px 0; }
          .nav-buttons a { 
            background: #007bff; color: white; padding: 12px 24px; 
            text-decoration: none; border-radius: 4px; margin: 5px;
            display: inline-block;
          }
          .nav-buttons a:hover { background: #0056b3; }
          .clean-storage { background: #6f42c1; }
          .clean-storage:hover { background: #5a2d91; }
          .analyze { background: #28a745; }
          .analyze:hover { background: #1e7e34; }
        </style>
      </head>
      <body>
        <h1 style="color: #2c3e50;">🛡️ SOC Downloaded Files</h1>
        <p><strong>Directory:</strong> /tmp/downloads (File Analyzer)</p>
        <p><em>Single file policy: Only one file stored at a time</em></p>
        
        ${fileLinks ? `
          <table>
            <tr style='background: #f8f9fa;'>
              <th style='padding: 15px;'>📄 File (Click to Download)</th>
              <th style='padding: 15px;'>Size</th>
              <th style='padding: 15px;'>SHA256 Hash</th>
            </tr>
            ${fileLinks}
          </table>
        ` : '<p>No files downloaded yet.</p>'}
        
        <div class="nav-buttons">
          <a href="/" class="analyze">← Analyze More Files</a>
          <a href="http://192.168.1.85:8000/list" target="_blank" class="clean-storage">View Clean Storage</a>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 30px;">
          <h3>📋 File Management</h3>
          <p><strong>Downloaded Files:</strong> Temporary files from analysis (this page)</p>
          <p><strong>Clean Storage:</strong> Verified safe files stored permanently</p>
          <p><strong>Downloads:</strong> Click any filename above to download the file</p>
        </div>
      </body>
      </html>
    `;
    
    res.send(enhancedHtml);
    
  } catch (error) {
    log(`ERROR in files endpoint: ${error.message}`);
    res.status(500).send(`
      <html>
      <body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
        <h2 style="color: red;">❌ Error Loading Files</h2>
        <p><strong>Error:</strong> ${error.message}</p>
        <a href="/" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Back to Home</a>
      </body>
      </html>
    `);
  }
});

// File download endpoint
app.get('/download/:filename', async (req, res) => {
  const filename = req.params.filename;
  log(`Download requested: ${filename}`);
  
  try {
    // Fetch file from file-analyzer container
    const response = await fetch(`http://file-analyzer:5000/download/${encodeURIComponent(filename)}`);
    
    if (!response.ok) {
      if (response.status === 404) {
        return res.status(404).send(`
          <html>
          <body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
            <h2 style="color: red;">❌ File Not Found</h2>
            <p><strong>File:</strong> ${filename}</p>
            <p>The file may have been replaced by a newer download (single file policy).</p>
            <a href="/files" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Back to Files</a>
          </body>
          </html>
        `);
      }
      throw new Error(`File-analyzer returned ${response.status}`);
    }
    
    // Get file content and headers
    const fileBuffer = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    
    // Set appropriate headers for download
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', fileBuffer.byteLength);
    
    // Send file
    res.send(Buffer.from(fileBuffer));
    log(`✅ Downloaded: ${filename} (${fileBuffer.byteLength} bytes)`);
    
  } catch (error) {
    log(`ERROR downloading ${filename}: ${error.message}`);
    res.status(500).send(`
      <html>
      <body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
        <h2 style="color: red;">❌ Download Failed</h2>
        <p><strong>File:</strong> ${filename}</p>
        <p><strong>Error:</strong> ${error.message}</p>
        <a href="/files" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Back to Files</a>
      </body>
      </html>
    `);
  }
});

// Add logs endpoint
app.get('/logs', (req, res) => {
  try {
    const logs = fs.readFileSync(logFile, 'utf8');
    res.send(`<pre>${logs}</pre>`);
  } catch (error) {
    res.send(`Error reading logs: ${error.message}`);
  }
});

https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
  log(`SOC Web UI running on HTTPS port ${PORT}`);
});