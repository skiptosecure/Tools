#!/usr/bin/env python3
"""
SOC Clean Storage Service - STIG Compliant with HTTPS
Stores and serves verified clean files
"""
import os
import ssl
import hashlib
import logging
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_file, Response
from marshmallow import Schema, fields, ValidationError
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Storage directory
STORAGE_DIR = Path('/app/storage')
STORAGE_DIR.mkdir(exist_ok=True)

# Metadata directory for file info
METADATA_DIR = Path('/app/metadata')
METADATA_DIR.mkdir(exist_ok=True)

# Initialize directories and logging when module loads (for gunicorn)
logger.info(f"Clean Storage Service starting - Storage: {STORAGE_DIR}")

class FileStorageSchema(Schema):
    filename = fields.Str(required=True)
    file_hash = fields.Str(required=True)
    source_url = fields.Str(required=False)
    scan_results = fields.Dict(required=False)

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def save_metadata(filename, metadata):
    """Save file metadata as JSON"""
    metadata_file = METADATA_DIR / f"{filename}.json"
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)

def load_metadata(filename):
    """Load file metadata"""
    metadata_file = METADATA_DIR / f"{filename}.json"
    if metadata_file.exists():
        with open(metadata_file, 'r') as f:
            return json.load(f)
    return {}

def clear_clean_storage():
    """Clear all files from clean storage (single file policy)"""
    try:
        # Clear storage files
        for file_path in STORAGE_DIR.iterdir():
            if file_path.is_file():
                file_path.unlink()
                logger.info(f"🗑️ Removed previous clean file: {file_path.name}")
        
        # Clear metadata files
        for metadata_path in METADATA_DIR.iterdir():
            if metadata_path.is_file() and metadata_path.suffix == '.json':
                metadata_path.unlink()
                logger.info(f"🗑️ Removed metadata: {metadata_path.name}")
                
    except Exception as e:
        logger.warning(f"Error clearing clean storage: {e}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    storage_available = STORAGE_DIR.exists()
    file_count = len(list(STORAGE_DIR.glob('*'))) if storage_available else 0
    
    return jsonify({
        "status": "healthy", 
        "service": "clean-storage-https",
        "storage_available": storage_available,
        "files_stored": file_count
    })

@app.route('/store', methods=['POST'])
def store_clean_file():
    """Store a verified clean file"""
    try:
        # Clear previous clean files (single file policy)
        clear_clean_storage()
        
        # Handle file upload
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Get additional metadata from form
        source_url = request.form.get('source_url', '')
        scan_results = request.form.get('scan_results', '{}')
        
        # Validate and secure filename
        filename = secure_filename(file.filename)
        if not filename:
            filename = f"clean_file_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Save file
        file_path = STORAGE_DIR / filename
        file.save(file_path)
        
        # Calculate hash
        file_hash = calculate_file_hash(file_path)
        file_size = file_path.stat().st_size
        
        # Create metadata
        metadata = {
            "filename": filename,
            "original_filename": file.filename,
            "file_hash": file_hash,
            "size": file_size,
            "source_url": source_url,
            "scan_results": scan_results,
            "stored_at": datetime.now().isoformat(),
            "status": "clean"
        }
        
        # Save metadata
        save_metadata(filename, metadata)
        
        logger.info(f"✅ Stored clean file: {filename} ({file_size} bytes, hash: {file_hash[:12]}...)")
        
        return jsonify({
            "status": "stored",
            "message": "File stored successfully",
            "filename": filename,
            "hash": file_hash,
            "size": file_size
        })
        
    except Exception as e:
        logger.error(f"Storage error: {str(e)}")
        return jsonify({"error": f"Storage failed: {str(e)}"}), 500

@app.route('/retrieve/<filename>', methods=['GET'])
def retrieve_clean_file(filename):
    """Retrieve a stored clean file"""
    try:
        # Secure the filename
        safe_filename = secure_filename(filename)
        file_path = STORAGE_DIR / safe_filename
        
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        
        # Load metadata
        metadata = load_metadata(safe_filename)
        
        logger.info(f"📤 Serving clean file: {safe_filename}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=metadata.get('original_filename', safe_filename)
        )
        
    except Exception as e:
        logger.error(f"Retrieval error: {str(e)}")
        return jsonify({"error": f"Retrieval failed: {str(e)}"}), 500

@app.route('/list', methods=['GET'])
def list_clean_files():
    """List all stored clean files with HTML interface"""
    try:
        files = []
        for file_path in STORAGE_DIR.glob('*'):
            if file_path.is_file():
                # Load metadata
                metadata = load_metadata(file_path.name)
                
                file_info = {
                    "filename": file_path.name,
                    "size": file_path.stat().st_size,
                    "hash": metadata.get('file_hash', 'unknown'),
                    "stored_at": metadata.get('stored_at', 'unknown'),
                    "source_url": metadata.get('source_url', ''),
                    "status": metadata.get('status', 'unknown'),
                    "scan_results": metadata.get('scan_results', '')
                }
                files.append(file_info)
        
        # Sort by stored date (newest first)
        files.sort(key=lambda x: x.get('stored_at', ''), reverse=True)
        
        total_size = sum(f['size'] for f in files)
        
        # Generate HTML response
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SOC Clean Storage</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    max-width: 1200px; 
                    margin: 20px auto; 
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                h1 {{ color: #2c3e50; text-align: center; }}
                .branding {{
                    text-align: center;
                    color: #7f8c8d;
                    font-style: italic;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                h2 {{ color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin: 20px 0; 
                }}
                th, td {{ 
                    border: 1px solid #ddd; 
                    padding: 12px; 
                    text-align: left; 
                }}
                th {{ 
                    background: #f8f9fa; 
                    font-weight: bold; 
                    color: #2c3e50;
                }}
                tr:nth-child(even) {{ background: #f9f9f9; }}
                tr:hover {{ background: #e8f4f8; }}
                a {{ 
                    color: #3498db; 
                    text-decoration: none; 
                    font-weight: bold;
                }}
                a:hover {{ 
                    color: #2980b9; 
                    text-decoration: underline; 
                }}
                .stats {{ 
                    background: #e8f6f3; 
                    padding: 15px; 
                    border-radius: 6px; 
                    margin: 20px 0;
                    border-left: 4px solid #27ae60;
                }}
                .nav-buttons {{ margin: 30px 0; text-align: center; }}
                .nav-buttons a {{ 
                    background: #3498db; 
                    color: white; 
                    padding: 12px 24px; 
                    text-decoration: none; 
                    border-radius: 4px; 
                    margin: 5px;
                    display: inline-block;
                }}
                .nav-buttons a:hover {{ background: #2980b9; }}
                .hash {{ 
                    font-family: monospace; 
                    font-size: 11px; 
                    color: #7f8c8d;
                }}
                .empty {{ 
                    text-align: center; 
                    color: #7f8c8d; 
                    font-style: italic; 
                    padding: 50px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>&#x1F6E1;&#xFE0F; SOC Clean Storage Repository</h1>
                <div class="branding">By skip to secure</div>
                
                <div class="stats">
                    <h3>📊 Storage Statistics</h3>
                    <p><strong>Files Stored:</strong> {len(files)} clean files</p>
                    <p><strong>Total Size:</strong> {total_size:,} bytes ({total_size/1024/1024:.2f} MB)</p>
                    <p><strong>Storage Directory:</strong> {STORAGE_DIR}</p>
                    <p><strong>Security Policy:</strong> Single file only - auto-clears on new uploads</p>
                </div>
        """
        
        if files:
            html += """
                <h2>📁 Stored Clean Files</h2>
                <table>
                    <tr>
                        <th>📄 Filename</th>
                        <th>📏 Size</th>
                        <th>🔍 SHA256 Hash</th>
                        <th>🌐 Source URL</th>
                        <th>📅 Stored</th>
                        <th>🛡️ Scan Results</th>
                        <th>⬇️ Download</th>
                    </tr>
            """
            
            for file_info in files:
                # Format stored date
                stored_date = file_info['stored_at']
                if stored_date != 'unknown':
                    try:
                        dt = datetime.fromisoformat(stored_date.replace('Z', '+00:00'))
                        stored_date = dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass
                
                # Truncate long URLs
                source_url = file_info['source_url']
                display_url = source_url[:50] + '...' if len(source_url) > 50 else source_url
                
                # Format hash
                hash_display = file_info['hash'][:16] + '...' if len(file_info['hash']) > 16 else file_info['hash']
                
                html += f"""
                    <tr>
                        <td><strong>{file_info['filename']}</strong></td>
                        <td>{file_info['size']:,} bytes</td>
                        <td class="hash" title="{file_info['hash']}">{hash_display}</td>
                        <td><a href="{source_url}" target="_blank" title="{source_url}">{display_url}</a></td>
                        <td>{stored_date}</td>
                        <td>{file_info['scan_results']}</td>
                        <td><a href="/retrieve/{file_info['filename']}" download="{file_info['filename']}">⬇️ Download</a></td>
                    </tr>
                """
            
            html += "</table>"
        else:
            html += """
                <div class="empty">
                    <h3>📭 No Clean Files Stored Yet</h3>
                    <p>Verified clean files will appear here after analysis.</p>
                </div>
            """
        
        html += """
                <div class="nav-buttons">
                    <a href="#" onclick="window.open('https://' + window.location.hostname + ':3000', '_blank')">🔍 Analyze Files</a>
                </div>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 30px;">
                    <h3>ℹ️ About Clean Storage</h3>
                    <p><strong>Purpose:</strong> Stores files that have been verified as clean by VirusTotal analysis</p>
                    <p><strong>Security:</strong> All files undergo URL and content scanning before storage</p>
                    <p><strong>Policy:</strong> Single file storage - previous files auto-deleted on new uploads</p>
                    <p><strong>Access:</strong> Files can be safely downloaded for SOC operations</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        logger.error(f"List error: {str(e)}")
        return f"""
        <html>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
            <h2 style="color: red;">❌ Error Loading Clean Storage</h2>
            <p><strong>Error:</strong> {str(e)}</p>
            <a href="https://{request.host.split(':')[0]}:3000" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Back to Analyzer</a>
        </body>
        </html>
        """, 500

@app.route('/verify/<filename>', methods=['GET'])
def verify_file_integrity(filename):
    """Verify file integrity using stored hash"""
    try:
        safe_filename = secure_filename(filename)
        file_path = STORAGE_DIR / safe_filename
        
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        
        # Load stored metadata
        metadata = load_metadata(safe_filename)
        stored_hash = metadata.get('file_hash')
        
        if not stored_hash:
            return jsonify({"error": "No hash found for verification"}), 400
        
        # Calculate current hash
        current_hash = calculate_file_hash(file_path)
        
        # Compare hashes
        is_valid = current_hash == stored_hash
        
        result = {
            "filename": safe_filename,
            "is_valid": is_valid,
            "stored_hash": stored_hash,
            "current_hash": current_hash,
            "status": "verified" if is_valid else "corrupted"
        }
        
        if not is_valid:
            logger.warning(f"⚠️  File integrity check failed for {safe_filename}")
        else:
            logger.info(f"✅ File integrity verified for {safe_filename}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500

@app.route('/stats', methods=['GET'])
def storage_stats():
    """Get storage statistics"""
    try:
        files = list(STORAGE_DIR.glob('*'))
        file_count = len([f for f in files if f.is_file()])
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        
        return jsonify({
            "status": "success",
            "stats": {
                "file_count": file_count,
                "total_size": total_size,
                "storage_used": total_size,
                "storage_directory": str(STORAGE_DIR)
            }
        })
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({"error": "Failed to get stats"}), 500

if __name__ == '__main__':
    # Use HTTP for internal Docker communication
    logger.info("🔒 Starting HTTP server on port 8000 for internal communication")
    app.run(host='0.0.0.0', port=8000, debug=False)
