#!/usr/bin/env python3
"""
Zeek Dashboard Generator
Creates HTML dashboard from Zeek log files
Usage: python zeekdash.py <directory_with_zeek_logs>
"""

import os
import sys
import glob
from datetime import datetime
import argparse

def parse_zeek_log(log_file_path):
    """Parse a Zeek log file and return structured data"""
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {log_file_path}: {e}")
        return None
    
    separator = '\t'
    fields = []
    types = []
    data_rows = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.startswith('#separator'):
            parts = line.split('\t')
            if len(parts) > 1:
                separator = parts[1].replace('\\x09', '\t')
        elif line.startswith('#fields'):
            parts = line.split('\t')
            if len(parts) > 1:
                fields = parts[1:]
        elif line.startswith('#types'):
            parts = line.split('\t')
            if len(parts) > 1:
                types = parts[1:]
        elif not line.startswith('#') and line and fields:
            try:
                row_data = line.split(separator)
                if len(row_data) >= len(fields):
                    row_dict = {}
                    for i, field in enumerate(fields):
                        if i < len(row_data):
                            row_dict[field] = row_data[i]
                        else:
                            row_dict[field] = '-'
                    data_rows.append(row_dict)
                elif len(row_data) == len(fields):
                    data_rows.append(dict(zip(fields, row_data)))
            except Exception:
                continue
    
    return {
        'fields': fields,
        'types': types,
        'data': data_rows,
        'count': len(data_rows)
    }

def format_timestamp(ts_str):
    """Convert Zeek timestamp to readable format"""
    try:
        ts = float(ts_str)
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ts_str

def analyze_connections(conn_data):
    """Analyze connection log for key insights"""
    if not conn_data or not conn_data['data']:
        return {}
    
    analysis = {
        'total_connections': len(conn_data['data']),
        'unique_destinations': len(set(row.get('id.resp_h', '') for row in conn_data['data'])),
        'protocols': {},
        'services': {},
        'external_ips': [],
        'unusual_ports': []
    }
    
    common_ports = ['80', '443', '53', '22', '21', '25', '110', '143', '993', '995']
    
    for row in conn_data['data']:
        proto = row.get('proto', 'unknown')
        analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1
        
        service = row.get('service', 'unknown')
        if service != '-':
            analysis['services'][service] = analysis['services'].get(service, 0) + 1
        
        resp_port = row.get('id.resp_p', '')
        if resp_port and resp_port not in common_ports and resp_port.isdigit():
            port_num = int(resp_port)
            if port_num > 1024 and port_num not in [8080, 8443]:
                analysis['unusual_ports'].append(f"{row.get('id.resp_h')}:{resp_port}")
        
        resp_ip = row.get('id.resp_h', '')
        if resp_ip and not any(resp_ip.startswith(prefix) for prefix in ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.', '169.254.']):
            if resp_ip != '255.255.255.255':
                analysis['external_ips'].append(resp_ip)
    
    analysis['external_ips'] = list(set(analysis['external_ips']))
    analysis['unusual_ports'] = list(set(analysis['unusual_ports']))
    
    return analysis

def analyze_http_activity(http_data):
    """Analyze HTTP log for suspicious activity"""
    if not http_data or not http_data['data']:
        return {}
    
    analysis = {
        'total_requests': len(http_data['data']),
        'suspicious_downloads': [],
        'post_requests': [],
        'user_agents': set(),
        'hosts': set(),
        'suspicious_uris': []
    }
    
    suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js']
    suspicious_keywords = ['update', 'download', 'install', 'setup', 'payload', 'shell', 'cmd']
    
    for row in http_data['data']:
        uri = row.get('uri', '')
        host = row.get('host', '')
        user_agent = row.get('user_agent', '')
        method = row.get('method', '')
        
        if any(ext in uri.lower() for ext in suspicious_extensions):
            analysis['suspicious_downloads'].append({
                'host': host,
                'uri': uri,
                'user_agent': user_agent,
                'timestamp': format_timestamp(row.get('ts', ''))
            })
        
        if method == 'POST':
            analysis['post_requests'].append({
                'host': host,
                'uri': uri,
                'method': method,
                'timestamp': format_timestamp(row.get('ts', ''))
            })
        
        if any(keyword in uri.lower() for keyword in suspicious_keywords):
            analysis['suspicious_uris'].append({
                'host': host,
                'uri': uri,
                'timestamp': format_timestamp(row.get('ts', ''))
            })
        
        if user_agent and user_agent != '-':
            analysis['user_agents'].add(user_agent)
        if host and host != '-':
            analysis['hosts'].add(host)
    
    analysis['user_agents'] = list(analysis['user_agents'])
    analysis['hosts'] = list(analysis['hosts'])
    
    return analysis

def analyze_ssl_activity(ssl_data):
    """Analyze SSL/TLS connections"""
    if not ssl_data or not ssl_data['data']:
        return {}
    
    analysis = {
        'total_ssl_connections': len(ssl_data['data']),
        'ssl_versions': {},
        'server_names': set(),
        'self_signed_certs': []
    }
    
    for row in ssl_data['data']:
        version = row.get('version', 'unknown')
        analysis['ssl_versions'][version] = analysis['ssl_versions'].get(version, 0) + 1
        
        server_name = row.get('server_name', '')
        if server_name and server_name != '-':
            analysis['server_names'].add(server_name)
        
        subject = row.get('subject', '')
        issuer = row.get('issuer', '')
        
        if subject and issuer and subject == issuer and subject != '-':
            analysis['self_signed_certs'].append({
                'server_name': server_name,
                'subject': subject,
                'ip': row.get('id.resp_h', ''),
                'timestamp': format_timestamp(row.get('ts', ''))
            })
    
    analysis['server_names'] = list(analysis['server_names'])
    return analysis

def analyze_files(files_data):
    """Analyze file transfers"""
    if not files_data or not files_data['data']:
        return {}
    
    analysis = {
        'total_files': len(files_data['data']),
        'file_types': {},
        'executable_files': [],
        'large_files': []
    }
    
    for row in files_data['data']:
        mime_type = row.get('mime_type', 'unknown')
        analysis['file_types'][mime_type] = analysis['file_types'].get(mime_type, 0) + 1
        
        filename = row.get('filename', '')
        file_size = row.get('seen_bytes', '0')
        
        if 'exe' in mime_type.lower() or 'application/x-dosexec' in mime_type:
            analysis['executable_files'].append({
                'filename': filename if filename != '-' else 'Unknown',
                'mime_type': mime_type,
                'size': file_size,
                'source': row.get('source', ''),
                'timestamp': format_timestamp(row.get('ts', ''))
            })
        
        try:
            if int(file_size) > 10485760:
                analysis['large_files'].append({
                    'filename': filename if filename != '-' else 'Unknown',
                    'mime_type': mime_type,
                    'size': file_size,
                    'timestamp': format_timestamp(row.get('ts', ''))
                })
        except:
            pass
    
    return analysis

def generate_threat_assessment(conn_analysis, http_analysis, ssl_analysis, files_analysis):
    """Generate dynamic threat assessment based on actual findings"""
    threats = []
    threat_level = "info"
    
    if len(http_analysis.get('suspicious_downloads', [])) > 0:
        threats.append(f"{len(http_analysis['suspicious_downloads'])} suspicious file downloads")
        threat_level = "warning"
    
    if len(http_analysis.get('post_requests', [])) > 5:
        threats.append(f"{len(http_analysis['post_requests'])} POST requests (potential data exfiltration)")
        if threat_level == "info":
            threat_level = "warning"
    
    if len(files_analysis.get('executable_files', [])) > 0:
        threats.append(f"{len(files_analysis['executable_files'])} executable files transferred")
        threat_level = "warning"
    
    if len(ssl_analysis.get('self_signed_certs', [])) > 0:
        threats.append(f"{len(ssl_analysis['self_signed_certs'])} self-signed certificates")
        if threat_level == "info":
            threat_level = "warning"
    
    if len(conn_analysis.get('unusual_ports', [])) > 10:
        threats.append(f"{len(conn_analysis['unusual_ports'])} connections to unusual ports")
        if threat_level == "info":
            threat_level = "warning"
    
    if not threats:
        return {
            'level': 'info',
            'icon': '✅',
            'title': 'NO THREATS DETECTED',
            'message': 'Network traffic analysis completed. No obvious security threats or suspicious activity detected.'
        }
    elif threat_level == "warning":
        return {
            'level': 'warning',
            'icon': '⚠️',
            'title': 'POTENTIAL THREATS DETECTED',
            'message': f"Analysis identified potential security concerns: {', '.join(threats)}. Review findings for false positives."
        }
    else:
        return {
            'level': 'alert',
            'icon': '🚨',
            'title': 'THREATS DETECTED',
            'message': f"Multiple threat indicators found: {', '.join(threats)}. Immediate investigation recommended."
        }

def generate_log_tables(zeek_logs):
    """Generate HTML tables for detailed log data"""
    html_parts = []
    
    for log_name, log_data in zeek_logs.items():
        if not log_data or log_data["count"] == 0:
            continue
            
        header_cells = ''.join(f'<th>{field}</th>' for field in log_data["fields"][:8])
        
        data_rows = []
        for row in log_data["data"][:50]:
            cells = []
            for field in log_data["fields"][:8]:
                cell_value = format_timestamp(row[field]) if field == "ts" else row.get(field, "-")
                cells.append(f'<td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">{cell_value}</td>')
            data_rows.append('<tr>' + ''.join(cells) + '</tr>')
        
        if log_data["count"] > 50:
            colspan = len(log_data["fields"][:8])
            more_row = f'<tr><td colspan="{colspan}" style="text-align: center; font-style: italic; color: #7f8c8d;">... and {log_data["count"] - 50} more entries</td></tr>'
            data_rows.append(more_row)
        
        table_html = f'''
        <details style="margin: 20px 0;">
            <summary>{log_name.upper()} Log - {log_data["count"]} entries</summary>
            <div class="table-container">
                <table>
                    <tr>{header_cells}</tr>
                    {''.join(data_rows)}
                </table>
            </div>
        </details>
        '''
        html_parts.append(table_html)
    
    return ''.join(html_parts)

def generate_html_report(zeek_logs, output_file, log_dir_name):
    """Generate comprehensive HTML report"""
    
    conn_analysis = analyze_connections(zeek_logs.get('conn'))
    http_analysis = analyze_http_activity(zeek_logs.get('http'))
    ssl_analysis = analyze_ssl_activity(zeek_logs.get('ssl'))
    files_analysis = analyze_files(zeek_logs.get('files'))
    
    threat_assessment = generate_threat_assessment(conn_analysis, http_analysis, ssl_analysis, files_analysis)
    
    if not any([conn_analysis.get('total_connections', 0), http_analysis.get('total_requests', 0), ssl_analysis.get('total_ssl_connections', 0), files_analysis.get('total_files', 0)]):
        total_activity = "No network activity detected"
    else:
        total_activity = f"Analysis of {conn_analysis.get('total_connections', 0)} connections across {len(zeek_logs)} log types"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeek Network Security Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        
        .header h1 {{
            color: #1e3c72;
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 1.1rem;
            margin-bottom: 20px;
        }}
        
        .header .branding {{
            color: #2a5298;
            font-size: 0.9rem;
            font-weight: 600;
            text-align: right;
            margin-bottom: 15px;
        }}
        
        .alert {{
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }}
        
        .alert.warning {{
            background: linear-gradient(45deg, #ffa726, #ffcc02);
        }}
        
        .alert.info {{
            background: linear-gradient(45deg, #42a5f5, #478ed1);
        }}
        
        .alert.alert {{
            background: linear-gradient(45deg, #ff6b6b, #ff8e8e);
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 45px rgba(0, 0, 0, 0.15);
        }}
        
        .card h2 {{
            color: #1e3c72;
            border-bottom: 3px solid #2a5298;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.4rem;
        }}
        
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-box {{
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(30, 60, 114, 0.3);
        }}
        
        .stat-number {{
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }}
        
        .stat-label {{
            font-size: 0.9rem;
            opacity: 0.9;
            margin-top: 5px;
        }}
        
        .table-container {{
            max-height: 400px;
            overflow-y: auto;
            border-radius: 10px;
            box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.1);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        
        th {{
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            padding: 12px 8px;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        td {{
            padding: 10px 8px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        
        tr:hover {{
            background-color: #e3f2fd;
        }}
        
        .tag {{
            display: inline-block;
            background: #2a5298;
            color: white;
            padding: 4px 8px;
            border-radius: 15px;
            font-size: 0.8rem;
            margin: 2px;
        }}
        
        .tag.suspicious {{
            background: #e74c3c;
        }}
        
        .tag.warning {{
            background: #f39c12;
        }}
        
        .tag.info {{
            background: #2ecc71;
        }}
        
        .list-item {{
            background: #f8f9fa;
            margin: 5px 0;
            padding: 10px;
            border-radius: 8px;
            border-left: 4px solid #2a5298;
        }}
        
        .list-item.suspicious {{
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }}
        
        .list-item.warning {{
            border-left-color: #f39c12;
            background: #fef8e6;
        }}
        
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.85rem;
            font-family: monospace;
        }}
        
        .code {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
        }}
        
        details {{
            margin: 15px 0;
        }}
        
        summary {{
            cursor: pointer;
            padding: 10px;
            background: #ecf0f1;
            border-radius: 5px;
            font-weight: 600;
            margin-bottom: 10px;
        }}
        
        summary:hover {{
            background: #d5dbdb;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: rgba(255, 255, 255, 0.8);
            margin-top: 50px;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="branding">by Skip to Secure</div>
            <h1>🛡️ Zeek Network Security Analysis</h1>
            <div class="subtitle">{total_activity} • Source: {log_dir_name} • Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            
            <div class="alert {threat_assessment['level']}">
                <strong>{threat_assessment['icon']} {threat_assessment['title']}:</strong> {threat_assessment['message']}
            </div>
            
            <div class="stat-grid">
                <div class="stat-box">
                    <span class="stat-number">{conn_analysis.get('total_connections', 0)}</span>
                    <div class="stat-label">Total Connections</div>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{len(zeek_logs)}</span>
                    <div class="stat-label">Log Types</div>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{len(conn_analysis.get('external_ips', []))}</span>
                    <div class="stat-label">External IPs</div>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{files_analysis.get('total_files', 0)}</span>
                    <div class="stat-label">Files Transferred</div>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>🌐 Network Connections</h2>
                {f'<div class="alert info"><strong>Analysis:</strong> {conn_analysis.get("total_connections", 0)} total connections to {conn_analysis.get("unique_destinations", 0)} unique destinations</div>' if conn_analysis.get('total_connections', 0) > 0 else '<div class="empty-state">No network connections detected</div>'}
                
                {f'''<details open>
                    <summary>Protocol Distribution</summary>
                    <div class="table-container">
                        <table>
                            <tr><th>Protocol</th><th>Count</th></tr>
                            {''.join(f'<tr><td>{proto}</td><td>{count}</td></tr>' for proto, count in conn_analysis.get('protocols', {}).items())}
                        </table>
                    </div>
                </details>''' if conn_analysis.get('protocols') else ''}
                
                {f'''<details>
                    <summary>External IP Addresses ({len(conn_analysis.get('external_ips', []))} unique)</summary>
                    {''.join(f'<div class="list-item"><span class="code">{ip}</span></div>' for ip in conn_analysis.get('external_ips', [])[:10])}
                    {f'<div class="list-item">... and {len(conn_analysis.get("external_ips", [])) - 10} more</div>' if len(conn_analysis.get('external_ips', [])) > 10 else ''}
                </details>''' if conn_analysis.get('external_ips') else ''}
                
                {f'''<details>
                    <summary>Unusual Ports ({len(conn_analysis.get('unusual_ports', []))} detected)</summary>
                    {''.join(f'<div class="list-item warning"><span class="code">{port}</span></div>' for port in conn_analysis.get('unusual_ports', [])[:10])}
                    {f'<div class="list-item">... and {len(conn_analysis.get("unusual_ports", [])) - 10} more</div>' if len(conn_analysis.get('unusual_ports', [])) > 10 else ''}
                </details>''' if conn_analysis.get('unusual_ports') else ''}
            </div>
            
            <div class="card">
                <h2>🌍 HTTP Activity</h2>
                {f'<div class="alert {"warning" if len(http_analysis.get("suspicious_downloads", [])) > 0 or len(http_analysis.get("post_requests", [])) > 5 else "info"}"><strong>Analysis:</strong> {http_analysis.get("total_requests", 0)} HTTP requests, {len(http_analysis.get("suspicious_downloads", []))} suspicious downloads, {len(http_analysis.get("post_requests", []))} POST requests</div>' if http_analysis.get('total_requests', 0) > 0 else '<div class="empty-state">No HTTP activity detected</div>'}
                
                {f'''<details {('open' if http_analysis.get('suspicious_downloads') else '')}>
                    <summary>Suspicious Downloads ({len(http_analysis.get('suspicious_downloads', []))})</summary>
                    <div class="table-container">
                        <table>
                            <tr><th>Host</th><th>File</th><th>Time</th></tr>
                            {''.join(f'<tr><td>{download["host"]}</td><td class="code">{download["uri"][:50]}...</td><td class="timestamp">{download["timestamp"]}</td></tr>' for download in http_analysis.get('suspicious_downloads', []))}
                        </table>
                    </div>
                </details>''' if http_analysis.get('suspicious_downloads') else ''}
                
                {f'''<details>
                    <summary>POST Requests ({len(http_analysis.get('post_requests', []))})</summary>
                    {''.join(f'<div class="list-item {"suspicious" if len(http_analysis.get("post_requests", [])) > 10 else ""}"><strong>{post["method"]}</strong> {post["host"]}<br><span class="code">{post["uri"][:80]}...</span><br><span class="timestamp">{post["timestamp"]}</span></div>' for post in http_analysis.get('post_requests', [])[:10])}
                    {f'<div class="list-item">... and {len(http_analysis.get("post_requests", [])) - 10} more</div>' if len(http_analysis.get('post_requests', [])) > 10 else ''}
                </details>''' if http_analysis.get('post_requests') else ''}
                
                {f'''<details>
                    <summary>User Agents ({len(http_analysis.get('user_agents', []))})</summary>
                    {''.join(f'<div class="list-item"><span class="code">{ua[:100]}...</span></div>' for ua in http_analysis.get('user_agents', [])[:5])}
                    {f'<div class="list-item">... and {len(http_analysis.get("user_agents", [])) - 5} more</div>' if len(http_analysis.get('user_agents', [])) > 5 else ''}
                </details>''' if http_analysis.get('user_agents') else ''}
            </div>
            
            <div class="card">
                <h2>🔒 SSL/TLS Analysis</h2>
                {f'<div class="alert {"warning" if len(ssl_analysis.get("self_signed_certs", [])) > 0 else "info"}"><strong>Overview:</strong> {ssl_analysis.get("total_ssl_connections", 0)} SSL connections, {len(ssl_analysis.get("self_signed_certs", []))} self-signed certificates</div>' if ssl_analysis.get('total_ssl_connections', 0) > 0 else '<div class="empty-state">No SSL/TLS activity detected</div>'}
                
                {f'''<details open>
                    <summary>SSL Versions</summary>
                    <div class="table-container">
                        <table>
                            <tr><th>Version</th><th>Count</th></tr>
                            {''.join(f'<tr><td>{version}</td><td>{count}</td></tr>' for version, count in ssl_analysis.get('ssl_versions', {}).items())}
                        </table>
                    </div>
                </details>''' if ssl_analysis.get('ssl_versions') else ''}
                
                {f'''<details>
                    <summary>Self-Signed Certificates ({len(ssl_analysis.get('self_signed_certs', []))})</summary>
                    {''.join(f'<div class="list-item suspicious"><strong>{cert["server_name"]}</strong><br><span class="code">{cert["ip"]}</span><br><span class="timestamp">{cert["timestamp"]}</span></div>' for cert in ssl_analysis.get('self_signed_certs', []))}
                </details>''' if ssl_analysis.get('self_signed_certs') else ''}
                
                {f'''<details>
                    <summary>Server Names ({len(ssl_analysis.get('server_names', []))} unique)</summary>
                    {''.join(f'<span class="tag info">{name}</span>' for name in sorted(ssl_analysis.get('server_names', []))[:20])}
                    {f'<div class="list-item">... and {len(ssl_analysis.get("server_names", [])) - 20} more</div>' if len(ssl_analysis.get('server_names', [])) > 20 else ''}
                </details>''' if ssl_analysis.get('server_names') else ''}
            </div>
            
            <div class="card">
                <h2>📁 File Transfers</h2>
                {f'<div class="alert {"warning" if len(files_analysis.get("executable_files", [])) > 0 else "info"}"><strong>Analysis:</strong> {files_analysis.get("total_files", 0)} files transferred, {len(files_analysis.get("executable_files", []))} executable files, {len(files_analysis.get("large_files", []))} large files</div>' if files_analysis.get('total_files', 0) > 0 else '<div class="empty-state">No file transfers detected</div>'}
                
                {f'''<details open>
                    <summary>File Types</summary>
                    <div class="table-container">
                        <table>
                            <tr><th>MIME Type</th><th>Count</th></tr>
                            {''.join(f'<tr><td class="code">{mime_type}</td><td>{count}</td></tr>' for mime_type, count in files_analysis.get('file_types', {}).items())}
                        </table>
                    </div>
                </details>''' if files_analysis.get('file_types') else ''}
                
                {f'''<details {('open' if files_analysis.get('executable_files') else '')}>
                    <summary>Executable Files ({len(files_analysis.get('executable_files', []))})</summary>
                    <div class="table-container">
                        <table>
                            <tr><th>Filename</th><th>Type</th><th>Size</th><th>Time</th></tr>
                            {''.join(f'<tr><td class="code">{file["filename"]}</td><td>{file["mime_type"]}</td><td>{file["size"]} bytes</td><td class="timestamp">{file["timestamp"]}</td></tr>' for file in files_analysis.get('executable_files', []))}
                        </table>
                    </div>
                </details>''' if files_analysis.get('executable_files') else ''}
                
                {f'''<details>
                    <summary>Large Files ({len(files_analysis.get('large_files', []))})</summary>
                    <div class="table-container">
                        <table>
                            <tr><th>Filename</th><th>Type</th><th>Size</th><th>Time</th></tr>
                            {''.join(f'<tr><td class="code">{file["filename"]}</td><td>{file["mime_type"]}</td><td>{file["size"]} bytes</td><td class="timestamp">{file["timestamp"]}</td></tr>' for file in files_analysis.get('large_files', []))}
                        </table>
                    </div>
                </details>''' if files_analysis.get('large_files') else ''}
            </div>
        </div>
        
        <!-- Detailed Log Tables -->
        {f'''<div class="card" style="margin: 20px 0;">
            <h2>📊 Detailed Log Analysis</h2>
            {generate_log_tables(zeek_logs)}
        </div>''' if any(log_data['count'] > 0 for log_data in zeek_logs.values()) else '<div class="card" style="margin: 20px 0;"><h2>📊 Detailed Log Analysis</h2><div class="empty-state">No log data available for detailed analysis</div></div>'}
        
        <div class="footer">
            <p>🔍 Analysis powered by Zeek Network Security Monitor</p>
            <p>Report generated by Zeek HTML Analyzer Tool</p>
        </div>
    </div>
    
    <script>
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {{
            // Add click events for better UX
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {{
                card.addEventListener('mouseenter', function() {{
                    this.style.transform = 'translateY(-5px)';
                }});
                card.addEventListener('mouseleave', function() {{
                    this.style.transform = 'translateY(0)';
                }});
            }});
            
            // Add search functionality to tables
            console.log('Zeek HTML Analyzer loaded successfully');
        }});
    </script>
</body>
</html>"""
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate HTML dashboard from Zeek logs')
    parser.add_argument('input_dir', nargs='?', default='.', help='Directory containing Zeek log files')
    parser.add_argument('-o', '--output', default='zeek_analysis.html', help='Output HTML file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_dir):
        print(f"Error: Directory {args.input_dir} not found")
        sys.exit(1)
    
    log_files = glob.glob(os.path.join(args.input_dir, '*.log'))
    
    if not log_files:
        print(f"No .log files found in {args.input_dir}")
        sys.exit(1)
    
    print(f"Found {len(log_files)} log files")
    
    zeek_logs = {}
    for log_file in log_files:
        log_name = os.path.basename(log_file).replace('.log', '')
        print(f"Processing {log_name}...")
        
        parsed_data = parse_zeek_log(log_file)
        if parsed_data:
            zeek_logs[log_name] = parsed_data
            print(f"  {parsed_data['count']} entries")
        else:
            print(f"  Failed to parse")
    
    if not zeek_logs:
        print("No valid log files could be parsed")
        sys.exit(1)
    
    output_path = os.path.join(args.input_dir, args.output)
    log_dir_name = os.path.basename(os.path.abspath(args.input_dir))
    
    print(f"\nGenerating HTML report...")
    generate_html_report(zeek_logs, output_path, log_dir_name)
    print(f"Success! Open {output_path} in your browser to view the analysis")

if __name__ == "__main__":
    main()
