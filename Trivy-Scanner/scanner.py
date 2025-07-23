import subprocess
import json
import re
import os
from datetime import datetime

def run_trivy_combined_scan(container_name):
    """Run Trivy scan with both vulnerability and secret scanning"""
    try:
        # Run trivy command with both scanners
        cmd = ['trivy', 'image', '--scanners', 'vuln,secret', '--format', 'json', '--insecure', container_name]
        
        # Set environment variables for insecure registries
        env = os.environ.copy()
        env['TRIVY_INSECURE'] = 'true'
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
        
        if result.returncode != 0:
            return {
                'success': False,
                'error': f"Trivy scan failed: {result.stderr}",
                'container_name': container_name
            }
        
        # Parse JSON output
        scan_data = json.loads(result.stdout)
        
        # Extract vulnerability counts
        vuln_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'negligible': 0
        }
        
        vulnerabilities = []
        secrets = []
        
        # Process results
        if 'Results' in scan_data:
            for result_item in scan_data['Results']:
                # Process vulnerabilities
                if 'Vulnerabilities' in result_item:
                    for vuln in result_item['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN').lower()
                        
                        # Count by severity
                        if severity in vuln_counts:
                            vuln_counts[severity] += 1
                        
                        # Store individual vulnerability
                        vulnerabilities.append({
                            'cve_id': vuln.get('VulnerabilityID', 'N/A'),
                            'severity': severity.upper(),
                            'package_name': vuln.get('PkgName', 'N/A'),
                            'installed_version': vuln.get('InstalledVersion', 'N/A'),
                            'fixed_version': vuln.get('FixedVersion', 'N/A'),
                            'title': vuln.get('Title', 'N/A'),
                            'description': vuln.get('Description', 'N/A')[:500]  # Limit description length
                        })
                
                # Process secrets
                if 'Secrets' in result_item:
                    for secret in result_item['Secrets']:
                        secrets.append({
                            'check_id': secret.get('RuleID', 'N/A'),
                            'status': 'FAIL',  # Trivy only reports exposed secrets
                            'title': secret.get('Title', 'N/A'),
                            'description': f"Secret found in {result_item.get('Target', 'unknown location')}: {secret.get('Match', 'N/A')[:100]}",
                            'severity': secret.get('Severity', 'HIGH').upper()
                        })
        
        # Create summary for secrets
        secret_summary = {
            'total_checks': len(secrets),
            'pass_count': 0,  # Trivy doesn't report passed checks
            'warn_count': len([s for s in secrets if s['severity'] in ['MEDIUM', 'LOW']]),
            'fail_count': len([s for s in secrets if s['severity'] in ['CRITICAL', 'HIGH']]),
            'info_count': len([s for s in secrets if s['severity'] == 'INFO']),
            'note_count': 0,
            'score': max(0, 100 - len(secrets))  # Simple scoring: 100 - number of secrets
        }
        
        return {
            'success': True,
            'container_name': container_name,
            'scan_date': datetime.now().isoformat(),
            'vulnerability_counts': vuln_counts,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'secret_results': {
                'summary': secret_summary,
                'checks': secrets
            }
        }
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': f"Trivy scan timed out for {container_name}",
            'container_name': container_name
        }
    except json.JSONDecodeError as e:
        return {
            'success': False,
            'error': f"Failed to parse Trivy output: {str(e)}",
            'container_name': container_name
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"Unexpected error: {str(e)}",
            'container_name': container_name
        }

def run_combined_scan(container_name):
    """Run Trivy combined scan (replaces separate Trivy + Docker Bench)"""
    print(f"Starting Trivy combined scan for: {container_name}")
    
    # Run Trivy with both vulnerability and secret scanning
    trivy_result = run_trivy_combined_scan(container_name)
    
    if not trivy_result['success']:
        return trivy_result
    
    # Prepare combined result (keeping same structure for compatibility)
    combined_result = {
        'success': True,
        'container_name': trivy_result['container_name'],
        'scan_date': trivy_result['scan_date'],
        'vulnerability_counts': trivy_result['vulnerability_counts'],
        'vulnerabilities': trivy_result['vulnerabilities'],
        'total_vulnerabilities': trivy_result['total_vulnerabilities']
    }
    
    # Add secret results as "bench_results" for database compatibility
    if trivy_result.get('secret_results'):
        combined_result['bench_results'] = trivy_result['secret_results']
        secret_count = trivy_result['secret_results']['summary']['total_checks']
        print(f"Trivy found {secret_count} exposed secrets")
    else:
        print("No exposed secrets found")
        combined_result['bench_results'] = None
    
    return combined_result

def test_scanner():
    """Test the combined scanner"""
    print("Testing Trivy combined scanner with nginx:alpine...")
    result = run_combined_scan('nginx:alpine')
    
    if result['success']:
        print(f"✅ Scan successful!")
        print(f"   Container: {result['container_name']}")
        print(f"   Total vulnerabilities: {result['total_vulnerabilities']}")
        print(f"   Critical: {result['vulnerability_counts']['critical']}")
        print(f"   High: {result['vulnerability_counts']['high']}")
        
        if result.get('bench_results'):
            secret_summary = result['bench_results']['summary']
            print(f"   Exposed secrets: {secret_summary['total_checks']}")
            print(f"   High risk secrets: {secret_summary['fail_count']}")
            print(f"   Medium risk secrets: {secret_summary['warn_count']}")
        else:
            print("   Secrets: Clean")
    else:
        print(f"❌ Scan failed: {result['error']}")
    
    return result

if __name__ == "__main__":
    test_scanner()
