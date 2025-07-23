from flask import Flask, request, jsonify
from scanner import run_combined_scan
from models import save_scan_results, get_all_scans, get_scan_details, get_dashboard_summary, delete_scan, get_db_connection
import os

app = Flask(__name__, static_folder='static', static_url_path='/static')

# Web Routes
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return app.send_static_file('dashboard.html')

# API Routes
@app.route('/api/scan', methods=['POST'])
def scan_container():
    """Scan a container using JSON POST data"""
    try:
        data = request.get_json()
        if not data or 'container_name' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing container_name in JSON body'
            }), 400
        
        container_name = data['container_name']
        print(f"Starting combined scan for: {container_name}")
        
        # Run the combined scan (Trivy + Docker Bench)
        scan_result = run_combined_scan(container_name)
        
        if not scan_result['success']:
            return jsonify({
                'success': False,
                'error': scan_result['error']
            }), 400
        
        # Save to database
        scan_id = save_scan_results(scan_result)
        
        if not scan_id:
            return jsonify({
                'success': False,
                'error': 'Failed to save scan results to database'
            }), 500
        
        # Prepare response with both vulnerability and bench data
        response_data = {
            'success': True,
            'scan_id': scan_id,
            'container_name': container_name,
            'vulnerability_counts': scan_result['vulnerability_counts'],
            'total_vulnerabilities': scan_result['total_vulnerabilities']
        }
        
        # Add bench results if available
        if scan_result.get('bench_results'):
            bench_summary = scan_result['bench_results']['summary']
            response_data['bench_summary'] = {
                'total_checks': bench_summary['total_checks'],
                'fail_count': bench_summary['fail_count'],
                'warn_count': bench_summary['warn_count'],
                'pass_count': bench_summary['pass_count'],
                'score': bench_summary['score']
            }
        
        return jsonify(response_data)
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Unexpected error: {str(e)}'
        }), 500

@app.route('/api/dashboard', methods=['GET'])
def dashboard_summary():
    """Get dashboard summary statistics"""
    summary = get_dashboard_summary()
    return jsonify({
        'success': True,
        'data': summary
    })

@app.route('/api/clear-data', methods=['POST'])
def clear_all_data():
    """Clear all scan data from the database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM bench_checks')
        cursor.execute('DELETE FROM bench_scans')
        cursor.execute('DELETE FROM vulnerabilities')
        cursor.execute('DELETE FROM scans')
        cursor.execute('DELETE FROM sqlite_sequence WHERE name IN ("scans", "vulnerabilities", "bench_scans", "bench_checks")')
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'All scan data cleared successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to clear data: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500

if __name__ == '__main__':
    print("Starting Security Dashboard Backend...")
    print("Available at: http://localhost:5001")
    
    # Make sure database exists
    if not os.path.exists('security_dashboard.db'):
        print("Database not found! Run 'python update_database.py' first.")
        exit(1)
    
    app.run(host='0.0.0.0', port=5001, debug=True)
