import sqlite3
from datetime import datetime

DATABASE_PATH = 'security_dashboard.db'

def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def save_scan_results(scan_result):
    """Save scan results to database (Trivy + Docker Bench)"""
    if not scan_result['success']:
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insert scan summary
        cursor.execute('''
            INSERT INTO scans (container_name, scan_date, total_critical, total_high, 
                             total_medium, total_low, total_negligible, scan_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_result['container_name'],
            scan_result['scan_date'],
            scan_result['vulnerability_counts']['critical'],
            scan_result['vulnerability_counts']['high'],
            scan_result['vulnerability_counts']['medium'],
            scan_result['vulnerability_counts']['low'],
            scan_result['vulnerability_counts']['negligible'],
            'completed'
        ))
        
        scan_id = cursor.lastrowid
        
        # Insert individual vulnerabilities
        for vuln in scan_result['vulnerabilities']:
            cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, cve_id, severity, package_name,
                                           installed_version, fixed_version, title, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln['cve_id'],
                vuln['severity'],
                vuln['package_name'],
                vuln['installed_version'],
                vuln['fixed_version'],
                vuln['title'],
                vuln['description']
            ))
        
        # Insert Docker Bench results if available
        if 'bench_results' in scan_result and scan_result['bench_results']:
            bench_data = scan_result['bench_results']
            summary = bench_data['summary']
            
            cursor.execute('''
                INSERT INTO bench_scans (scan_id, total_checks, pass_count, warn_count,
                                       fail_count, info_count, note_count, score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                summary['total_checks'],
                summary['pass_count'],
                summary['warn_count'],
                summary['fail_count'],
                summary['info_count'],
                summary['note_count'],
                summary['score']
            ))
            
            bench_scan_id = cursor.lastrowid
            
            # Insert individual bench checks
            for check in bench_data['checks']:
                cursor.execute('''
                    INSERT INTO bench_checks (bench_scan_id, check_id, status, title, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    bench_scan_id,
                    check['check_id'],
                    check['status'],
                    check['title'],
                    check['description']
                ))
        
        conn.commit()
        return scan_id
        
    except Exception as e:
        conn.rollback()
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

def get_all_scans(limit=20):
    """Get all scans summary with Docker Bench data - limited to prevent VM overload"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT s.id, s.container_name, s.scan_date, 
               s.total_critical, s.total_high, s.total_medium, s.total_low, s.total_negligible,
               b.total_checks, b.pass_count, b.warn_count, b.fail_count, b.info_count, b.note_count, b.score
        FROM scans s
        LEFT JOIN bench_scans b ON s.id = b.scan_id
        ORDER BY s.scan_date DESC
        LIMIT ?
    ''', (limit,))
    
    scans = []
    for row in cursor.fetchall():
        scan_dict = dict(row)
        # Add computed fields
        scan_dict['total_issues'] = scan_dict['total_critical'] + scan_dict['total_high'] + scan_dict['total_medium'] + scan_dict['total_low']
        scan_dict['config_issues'] = (scan_dict['fail_count'] or 0) + (scan_dict['warn_count'] or 0)
        scans.append(scan_dict)
    
    conn.close()
    return scans

def get_scan_details(scan_id):
    """Get detailed scan results including vulnerabilities and bench checks"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get scan info
    cursor.execute('''
        SELECT s.*, b.total_checks, b.pass_count, b.warn_count, b.fail_count, 
               b.info_count, b.note_count, b.score
        FROM scans s
        LEFT JOIN bench_scans b ON s.id = b.scan_id
        WHERE s.id = ?
    ''', (scan_id,))
    
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None
    
    # Get vulnerabilities for this scan
    cursor.execute('''
        SELECT * FROM vulnerabilities WHERE scan_id = ?
        ORDER BY 
            CASE severity 
                WHEN 'CRITICAL' THEN 1 
                WHEN 'HIGH' THEN 2 
                WHEN 'MEDIUM' THEN 3 
                WHEN 'LOW' THEN 4 
                ELSE 5 
            END
    ''', (scan_id,))
    
    vulnerabilities = [dict(row) for row in cursor.fetchall()]
    
    # Get bench checks for this scan
    cursor.execute('''
        SELECT bc.* FROM bench_checks bc
        JOIN bench_scans bs ON bc.bench_scan_id = bs.id
        WHERE bs.scan_id = ?
        ORDER BY 
            CASE bc.status
                WHEN 'FAIL' THEN 1
                WHEN 'WARN' THEN 2
                WHEN 'INFO' THEN 3
                WHEN 'NOTE' THEN 4
                WHEN 'PASS' THEN 5
                ELSE 6
            END
    ''', (scan_id,))
    
    bench_checks = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        'scan': dict(scan),
        'vulnerabilities': vulnerabilities,
        'bench_checks': bench_checks
    }

def get_dashboard_summary():
    """Get dashboard summary statistics - limited to most recent 20 scans"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total scanned containers (all time)
    cursor.execute('SELECT COUNT(*) as total_scans FROM scans')
    total_scans = cursor.fetchone()['total_scans']
    
    # Total critical issues across recent scans only (prevents VM overload)
    cursor.execute('''
        SELECT SUM(total_critical) as total_critical 
        FROM (
            SELECT total_critical FROM scans 
            ORDER BY scan_date DESC 
            LIMIT 20
        )
    ''')
    total_critical = cursor.fetchone()['total_critical'] or 0
    
    # Containers with high/critical issues (recent scans only)
    cursor.execute('''
        SELECT COUNT(*) as containers_with_issues 
        FROM (
            SELECT id FROM scans 
            WHERE total_critical > 0 OR total_high > 0
            ORDER BY scan_date DESC 
            LIMIT 20
        )
    ''')
    containers_with_issues = cursor.fetchone()['containers_with_issues']
    
    # Recent scans (last 20) with bench data
    cursor.execute('''
        SELECT s.container_name, s.scan_date, 
               s.total_critical, s.total_high, s.total_medium, s.total_low,
               b.fail_count, b.warn_count, b.score
        FROM scans s
        LEFT JOIN bench_scans b ON s.id = b.scan_id
        ORDER BY s.scan_date DESC 
        LIMIT 20
    ''')
    recent_scans = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        'total_scans': total_scans,
        'total_critical': total_critical,
        'containers_with_issues': containers_with_issues,
        'recent_scans': recent_scans
    }

def delete_scan(scan_id):
    """Delete a scan and its vulnerabilities and bench checks"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Delete bench checks first
        cursor.execute('''
            DELETE FROM bench_checks 
            WHERE bench_scan_id IN (
                SELECT id FROM bench_scans WHERE scan_id = ?
            )
        ''', (scan_id,))
        
        # Delete bench scans
        cursor.execute('DELETE FROM bench_scans WHERE scan_id = ?', (scan_id,))
        
        # Delete vulnerabilities
        cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        
        # Delete scan
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error deleting scan: {e}")
        return False
    finally:
        conn.close()
