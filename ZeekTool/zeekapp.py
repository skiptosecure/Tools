#!/usr/bin/env python3
"""
Zeek PCAP Processor
Runs Zeek analysis on PCAP files and generates logs
Usage: python zeekapp.py <path_to_pcap_file>
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

def check_requirements():
    """Check if required tools are available"""
    try:
        result = subprocess.run(['podman', '--version'], 
                              capture_output=True, text=True, check=True)
        print(f"Found podman: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: podman not found. Please install podman.")
        return False

def create_log_directory(pcap_path):
    """Create timestamped log directory"""
    pcap_name = Path(pcap_path).stem
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_dir = f"logs_{pcap_name}_{timestamp}"
    
    os.makedirs(log_dir, exist_ok=True)
    print(f"Created log directory: {log_dir}")
    return log_dir

def run_zeek_analysis(pcap_path, log_dir):
    """Run Zeek analysis using podman"""
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        return False
    
    # Get absolute paths
    pcap_abs = os.path.abspath(pcap_path)
    log_abs = os.path.abspath(log_dir)
    pcap_name = os.path.basename(pcap_abs)
    
    print(f"Analyzing PCAP: {pcap_name}")
    print(f"Output directory: {log_abs}")
    
    # Podman command to run Zeek - use :z instead of :Z to avoid SELinux issues
    podman_cmd = [
        'podman', 'run', '--rm',
        '-v', f'{pcap_abs}:/pcap/{pcap_name}:z',
        '-v', f'{log_abs}:/output:z',
        'docker.io/zeek/zeek:latest',
        'sh', '-c', f'cd /output && zeek -r /pcap/{pcap_name}'
    ]
    
    print("Running Zeek analysis...")
    print(f"Command: {' '.join(podman_cmd)}")
    
    try:
        result = subprocess.run(podman_cmd, 
                              capture_output=True, text=True, check=True)
        
        print("Zeek analysis completed successfully")
        if result.stdout:
            print(f"Zeek stdout: {result.stdout}")
        if result.stderr:
            print(f"Zeek stderr: {result.stderr}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Error running Zeek analysis:")
        print(f"Exit code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False

def check_log_files(log_dir):
    """Check what log files were generated"""
    log_files = []
    for file in os.listdir(log_dir):
        if file.endswith('.log'):
            file_path = os.path.join(log_dir, file)
            size = os.path.getsize(file_path)
            log_files.append((file, size))
    
    if log_files:
        print(f"\nGenerated {len(log_files)} log files:")
        for name, size in sorted(log_files):
            print(f"  {name}: {size} bytes")
    else:
        print("Warning: No log files generated")
    
    return len(log_files) > 0

def call_dashboard_generator(log_dir):
    """Call zeekdash.py to generate HTML dashboard"""
    dashboard_script = 'zeekdash.py'
    
    if not os.path.exists(dashboard_script):
        print(f"Warning: {dashboard_script} not found in current directory")
        print("You can run it manually with:")
        print(f"python zeekdash.py {log_dir}")
        return
    
    print(f"\nGenerating HTML dashboard...")
    try:
        cmd = ['python3', dashboard_script, log_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        print("Dashboard generated successfully")
        if result.stdout:
            print(result.stdout)
            
    except subprocess.CalledProcessError as e:
        print(f"Error generating dashboard:")
        print(f"Exit code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        print(f"Error: python3 not found")

def main():
    parser = argparse.ArgumentParser(description='Process PCAP file with Zeek')
    parser.add_argument('pcap_file', help='Path to PCAP file to analyze')
    parser.add_argument('--no-dashboard', action='store_true', 
                       help='Skip dashboard generation')
    
    args = parser.parse_args()
    
    print("Zeek PCAP Processor")
    print("==================")
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Validate PCAP file
    if not os.path.exists(args.pcap_file):
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    # Create log directory
    log_dir = create_log_directory(args.pcap_file)
    
    # Run Zeek analysis
    if not run_zeek_analysis(args.pcap_file, log_dir):
        print("Zeek analysis failed")
        sys.exit(1)
    
    # Check results
    if not check_log_files(log_dir):
        print("No log files generated - analysis may have failed")
        sys.exit(1)
    
    # Generate dashboard
    if not args.no_dashboard:
        call_dashboard_generator(log_dir)
    
    print(f"\nAnalysis complete!")
    print(f"Log files: {log_dir}/")
    print(f"Dashboard: {log_dir}/zeek_analysis.html")

if __name__ == "__main__":
    main()
