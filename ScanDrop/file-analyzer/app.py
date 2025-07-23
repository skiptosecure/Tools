#!/usr/bin/env python3
"""
SOC File Analyzer - Enhanced with VirusTotal Integration
"""

import os
import hashlib
import logging
import requests
import time
from pathlib import Path
from flask import Flask, request, jsonify
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Use internal container directory (no volume mounts)
DOWNLOAD_DIR = Path('/tmp/downloads')
DOWNLOAD_DIR.mkdir(exist_ok=True, mode=0o777)

# VirusTotal API configuration
VT_API_KEY = 'asd-PUT-YOUR-KEY-HERE-asd'
VT_API_URL = 'https://www.virustotal.com/vtapi/v2'

logger.info(f"File Analyzer Starting - Downloads go to: {DOWNLOAD_DIR}")
logger.info(f"VirusTotal API Key: {'✅ Configured' if VT_API_KEY else '❌ Missing'}")

def calculate_file_hashes(file_path):
    """Calculate multiple hashes for a file"""
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for hash_obj in hashes.values():
                hash_obj.update(chunk)
    
    return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}

def clear_downloads_directory():
    """Clear all files from downloads directory (single file policy)"""
    try:
        for file_path in DOWNLOAD_DIR.iterdir():
            if file_path.is_file():
                file_path.unlink()
                logger.info(f"🗑️  Removed previous file: {file_path.name}")
    except Exception as e:
        logger.warning(f"Error clearing downloads: {e}")

def scan_url_virustotal(url):
    """Scan URL with VirusTotal"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    try:
        # Submit URL for scanning
        params = {'apikey': VT_API_KEY, 'url': url}
        response = requests.post(f'{VT_API_URL}/url/scan', data=params, timeout=30)
        
        if response.status_code != 200:
            return {"error": f"VirusTotal API error: {response.status_code}"}
        
        result = response.json()
        return result
        
    except Exception as e:
        logger.error(f"VirusTotal URL scan error: {e}")
        return {"error": str(e)}

def scan_file_virustotal(file_path):
    """Scan file with VirusTotal using file hash"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    try:
        # Calculate file hash
        hashes = calculate_file_hashes(file_path)
        sha256_hash = hashes['sha256']
        
        # Query VirusTotal for existing scan results
        params = {'apikey': VT_API_KEY, 'resource': sha256_hash}
        response = requests.get(f'{VT_API_URL}/file/report', params=params, timeout=30)
        
        if response.status_code != 200:
            return {"error": f"VirusTotal API error: {response.status_code}"}
        
        result = response.json()
        
        # If file not found in VT database, upload it
        if result['response_code'] == 0:
            logger.info("File not in VirusTotal database, uploading...")
            return upload_file_virustotal(file_path)
        
        return result
        
    except Exception as e:
        logger.error(f"VirusTotal file scan error: {e}")
        return {"error": str(e)}

def upload_file_virustotal(file_path):
    """Upload file to VirusTotal for scanning"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f)}
            params = {'apikey': VT_API_KEY}
            response = requests.post(f'{VT_API_URL}/file/scan', files=files, data=params, timeout=60)
        
        if response.status_code != 200:
            return {"error": f"VirusTotal upload error: {response.status_code}"}
        
        result = response.json()
        result['uploaded'] = True
        return result
        
    except Exception as e:
        logger.error(f"VirusTotal upload error: {e}")
        return {"error": str(e)}

def format_vt_results(vt_result):
    """Format VirusTotal results for display"""
    if "error" in vt_result:
        return f"<div style='color: red;'>❌ VirusTotal Error: {vt_result['error']}</div>", False
    
    if vt_result.get('response_code') == 0:
        return "<div style='color: orange;'>⏳ File not yet analyzed by VirusTotal</div>", False
    
    if 'uploaded' in vt_result:
        return "<div style='color: blue;'>📤 File uploaded to VirusTotal for analysis</div>", False
    
    positives = vt_result.get('positives', 0)
    total = vt_result.get('total', 0)
    
    if positives == 0:
        status_color = "green"
        status_icon = "✅"
        status_text = "CLEAN"
        is_clean = True
    elif positives <= 2:
        status_color = "orange"
        status_icon = "⚠️"
        status_text = "SUSPICIOUS"
        is_clean = False
    else:
        status_color = "red"
        status_icon = "🚨"
        status_text = "MALICIOUS"
        is_clean = False
    
    result_html = f"""
    <div style='border: 2px solid {status_color}; padding: 15px; border-radius: 8px; margin: 10px 0;'>
        <h3 style='color: {status_color}; margin: 0;'>{status_icon} VirusTotal Scan Results: {status_text}</h3>
        <p><strong>Detection:</strong> {positives}/{total} engines detected threats</p>
        <p><strong>Scan Date:</strong> {vt_result.get('scan_date', 'Unknown')}</p>
        <p><strong>Permalink:</strong> <a href="{vt_result.get('permalink', '#')}" target="_blank">View Full Report</a></p>
    </div>
    """
    
    return result_html, is_clean

def store_clean_file(file_path, url, url_scan_result, file_scan_result):
    """Store verified clean file to clean storage service"""
    try:
        logger.info(f"Storing clean file to clean storage: {file_path.name}")
        
        # Prepare file for upload
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            data = {
                'source_url': url,
                'scan_results': f"URL: {url_scan_result.get('positives', 0)}/{url_scan_result.get('total', 0)}, File: {file_scan_result.get('positives', 0)}/{file_scan_result.get('total', 0)}"
            }
            
            # Send to clean storage
            response = requests.post('http://clean-storage:8000/store', files=files, data=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✅ File stored in clean storage: {result}")
                return True, result
            else:
                logger.error(f"❌ Clean storage error: {response.status_code} - {response.text}")
                return False, {"error": f"Storage failed: {response.status_code}"}
                
    except Exception as e:
        logger.error(f"❌ Error storing to clean storage: {e}")
        return False, {"error": str(e)}

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "file-analyzer"})

@app.route('/analyze', methods=['POST'])
def analyze_file():
    try:
        # Get URL
        if request.is_json:
            url = request.json.get('url')
        else:
            url = request.form.get('url')
        
        if not url:
            return "No URL provided", 400
        
        logger.info(f"Analyzing: {url}")
        
        # Clear previous downloads (single file policy)
        clear_downloads_directory()
        
        # Scan URL with VirusTotal first
        logger.info("Scanning URL with VirusTotal...")
        url_scan_result = scan_url_virustotal(url)
        
        # Download file
        logger.info("Downloading file...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Generate filename
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or 'downloaded_file'
        if '.' not in filename:
            content_type = response.headers.get('content-type', '')
            if 'json' in content_type:
                filename += '.json'
            elif 'html' in content_type:
                filename += '.html'
            elif 'icon' in content_type or 'image' in content_type:
                filename += '.ico'
            else:
                filename += '.bin'
        
        # Save to /tmp (always writable)
        file_path = DOWNLOAD_DIR / filename
        
        with open(file_path, 'wb') as f:
            f.write(response.content)
        
        file_size = len(response.content)
        logger.info(f"✅ Saved {filename} ({file_size} bytes) to {file_path}")
        
        # Calculate file hashes
        logger.info("Calculating file hashes...")
        hashes = calculate_file_hashes(file_path)
        
        # Scan file with VirusTotal
        logger.info("Scanning file with VirusTotal...")
        file_scan_result = scan_file_virustotal(file_path)
        
        # Format results
        url_scan_html, url_is_clean = format_vt_results(url_scan_result)
        file_scan_html, file_is_clean = format_vt_results(file_scan_result)
        
        # Check if file should be stored as clean or deleted if dirty
        storage_html = ""
        if url_is_clean and file_is_clean:
            logger.info("🎯 Both URL and file are clean - storing to clean storage")
            stored, storage_result = store_clean_file(file_path, url, url_scan_result, file_scan_result)
            
            if stored:
                storage_html = f"""
                <div style="background: #d4edda; border: 2px solid #28a745; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #155724; margin: 0;">🛡️ File Stored as Clean</h3>
                    <p><strong>Status:</strong> File has been automatically moved to clean storage</p>
                    <p><strong>Storage Hash:</strong> {storage_result.get('hash', 'unknown')[:16]}...</p>
                    <p><strong>Storage Size:</strong> {storage_result.get('size', 0):,} bytes</p>
                </div>
                """
            else:
                storage_html = f"""
                <div style="background: #fff3cd; border: 2px solid #ffc107; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #856404; margin: 0;">⚠️ Storage Warning</h3>
                    <p><strong>Issue:</strong> File is clean but could not be stored</p>
                    <p><strong>Error:</strong> {storage_result.get('error', 'Unknown error')}</p>
                </div>
                """
        elif not url_is_clean or not file_is_clean:
            # IMMEDIATELY DELETE DIRTY FILES
            logger.warning(f"🚨 File or URL flagged as dirty - deleting immediately: {file_path.name}")
            try:
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"🗑️ DELETED dirty file: {file_path.name}")
            except Exception as delete_error:
                logger.error(f"Error deleting dirty file: {delete_error}")
            
            storage_html = f"""
            <div style="background: #f8d7da; border: 2px solid #dc3545; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #721c24; margin: 0;">🚨 File Deleted Immediately</h3>
                <p><strong>Reason:</strong> File or URL flagged by VirusTotal as suspicious/malicious</p>
                <p><strong>Action:</strong> File has been permanently deleted for security</p>
                <p><strong>Status:</strong> No files remain on system</p>
            </div>
            """
        
        # Return comprehensive results page
        return f"""
        <html>
        <head><title>File Analysis Complete</title></head>
        <body style="font-family: Arial; max-width: 800px; margin: 20px auto; padding: 20px;">
            <h1 style="color: #2c3e50;">🛡️ SOC File Analysis Results</h1>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h2>📄 File Information</h2>
                <p><strong>Source URL:</strong> {url}</p>
                <p><strong>Filename:</strong> {filename}</p>
                <p><strong>Size:</strong> {file_size:,} bytes</p>
                <p><strong>Content Type:</strong> {response.headers.get('content-type', 'unknown')}</p>
                <p><strong>Saved to:</strong> {file_path}</p>
            </div>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h2>🔍 File Hashes</h2>
                <p><strong>MD5:</strong> <code>{hashes['md5']}</code></p>
                <p><strong>SHA1:</strong> <code>{hashes['sha1']}</code></p>
                <p><strong>SHA256:</strong> <code>{hashes['sha256']}</code></p>
            </div>
            
            <div style="margin: 20px 0;">
                <h2>🌐 URL Scan Results</h2>
                {url_scan_html}
            </div>
            
            <div style="margin: 20px 0;">
                <h2>📁 File Scan Results</h2>
                {file_scan_html}
            </div>
            
            {storage_html}
            
            <div style="margin: 30px 0;">
                <a href="/" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 5px;">← Analyze Another File</a>
                <a href="http://192.168.1.85:8000/list" target="_blank" style="background: #6f42c1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 5px;">View Clean Storage</a>
            </div>
        </body>
        </html>
        """
        
    except Exception as e:
        logger.error(f"❌ Analysis error: {e}")
        
        return f"""
        <html>
        <head><title>Analysis Failed</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
            <h2 style="color: red;">❌ Analysis Failed</h2>
            <p><strong>Error:</strong> {e}</p>
            <p><strong>URL:</strong> {request.form.get('url', 'unknown')}</p>
            <br>
            <a href="/" style="background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Try Again</a>
        </body>
        </html>
        """

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download a file from the downloads directory"""
    try:
        # Secure the filename to prevent directory traversal
        safe_filename = os.path.basename(filename)
        file_path = DOWNLOAD_DIR / safe_filename
        
        if not file_path.exists():
            logger.warning(f"Download requested for non-existent file: {safe_filename}")
            return "File not found", 404
        
        logger.info(f"📤 Serving download: {safe_filename}")
        
        # Read file and return as response
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Determine content type
        content_type = 'application/octet-stream'
        if safe_filename.endswith('.json'):
            content_type = 'application/json'
        elif safe_filename.endswith('.html'):
            content_type = 'text/html'
        elif safe_filename.endswith('.ico'):
            content_type = 'image/x-icon'
        elif safe_filename.endswith(('.jpg', '.jpeg')):
            content_type = 'image/jpeg'
        elif safe_filename.endswith('.png'):
            content_type = 'image/png'
        elif safe_filename.endswith('.txt'):
            content_type = 'text/plain'
        
        from flask import Response
        return Response(
            file_data,
            headers={
                'Content-Type': content_type,
                'Content-Disposition': f'attachment; filename="{safe_filename}"',
                'Content-Length': len(file_data)
            }
        )
        
    except Exception as e:
        logger.error(f"❌ Download error for {filename}: {e}")
        return f"Download failed: {str(e)}", 500

@app.route('/files', methods=['GET'])
def list_files():
    try:
        files = []
        total_size = 0
        
        if DOWNLOAD_DIR.exists():
            for file_path in DOWNLOAD_DIR.iterdir():
                if file_path.is_file():
                    size = file_path.stat().st_size
                    hashes = calculate_file_hashes(file_path)
                    files.append({
                        "filename": file_path.name,
                        "size": size,
                        "path": str(file_path),
                        "hashes": hashes
                    })
                    total_size += size
        
        html = f"""
        <html>
        <head><title>Downloaded Files</title></head>
        <body style="font-family: Arial; max-width: 1000px; margin: 50px auto; padding: 20px;">
            <h2>📁 Downloaded Files ({len(files)} files, {total_size:,} bytes total)</h2>
            <p><strong>Directory:</strong> {DOWNLOAD_DIR}</p>
            <p><em>Single file policy: Only one file stored at a time</em></p>
            <br>
        """
        
        if files:
            html += "<table border='1' style='width: 100%; border-collapse: collapse;'>"
            html += "<tr style='background: #f8f9fa;'><th style='padding: 10px;'>Filename</th><th style='padding: 10px;'>Size</th><th style='padding: 10px;'>SHA256 Hash</th></tr>"
            for file_info in files:
                html += f"""
                <tr>
                    <td style='padding: 10px;'>{file_info['filename']}</td>
                    <td style='padding: 10px;'>{file_info['size']:,} bytes</td>
                    <td style='padding: 10px; font-family: monospace; font-size: 11px;'>{file_info['hashes']['sha256']}</td>
                </tr>
                """
            html += "</table>"
        else:
            html += "<p>No files downloaded yet.</p>"
        
        html += """
            <br><br>
            <a href="/" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Analyze More Files</a>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"Error listing files: {e}", 500

if __name__ == '__main__':
    logger.info("Starting Enhanced File Analyzer with VirusTotal...")
    app.run(host='0.0.0.0', port=5000, debug=True)
