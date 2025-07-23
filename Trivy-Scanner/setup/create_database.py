#!/usr/bin/env python3
"""
Database setup script for Trivy Security Dashboard
Creates all necessary tables for vulnerability and secret scanning
"""

import sqlite3
import os
from datetime import datetime

DATABASE_PATH = 'security_dashboard.db'

def create_database():
    """Create the security dashboard database with all required tables"""
    
    # Remove existing database if it exists
    if os.path.exists(DATABASE_PATH):
        backup_name = f"security_dashboard_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        os.rename(DATABASE_PATH, backup_name)
        print(f"Existing database backed up as: {backup_name}")
    
    # Create new database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Create scans table (main scan results)
        cursor.execute('''
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_critical INTEGER DEFAULT 0,
                total_high INTEGER DEFAULT 0,
                total_medium INTEGER DEFAULT 0,
                total_low INTEGER DEFAULT 0,
                total_negligible INTEGER DEFAULT 0,
                scan_status TEXT DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create vulnerabilities table (individual CVEs)
        cursor.execute('''
            CREATE TABLE vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                cve_id TEXT,
                severity TEXT,
                package_name TEXT,
                installed_version TEXT,
                fixed_version TEXT,
                title TEXT,
                description TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Create bench_scans table (for secret detection summary - reusing old structure)
        cursor.execute('''
            CREATE TABLE bench_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                total_checks INTEGER DEFAULT 0,
                pass_count INTEGER DEFAULT 0,
                warn_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                note_count INTEGER DEFAULT 0,
                score INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Create bench_checks table (for individual secrets - reusing old structure)
        cursor.execute('''
            CREATE TABLE bench_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bench_scan_id INTEGER NOT NULL,
                check_id TEXT,
                status TEXT,
                title TEXT,
                description TEXT,
                FOREIGN KEY (bench_scan_id) REFERENCES bench_scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX idx_scans_container ON scans(container_name)')
        cursor.execute('CREATE INDEX idx_scans_date ON scans(scan_date)')
        cursor.execute('CREATE INDEX idx_vulns_scan_id ON vulnerabilities(scan_id)')
        cursor.execute('CREATE INDEX idx_vulns_severity ON vulnerabilities(severity)')
        cursor.execute('CREATE INDEX idx_bench_scans_scan_id ON bench_scans(scan_id)')
        cursor.execute('CREATE INDEX idx_bench_checks_bench_scan_id ON bench_checks(bench_scan_id)')
        
        conn.commit()
        print("Database created successfully!")
        print(f"Database file: {DATABASE_PATH}")
        
        # Display table info
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"Created {len(tables)} tables: {', '.join([t[0] for t in tables])}")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"Error creating database: {e}")
        return False
    finally:
        conn.close()

def verify_database():
    """Verify that the database was created correctly"""
    if not os.path.exists(DATABASE_PATH):
        print("Database file not found!")
        return False
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Check all tables exist
        required_tables = ['scans', 'vulnerabilities', 'bench_scans', 'bench_checks']
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        for table in required_tables:
            if table in existing_tables:
                print(f"Table '{table}' exists")
            else:
                print(f"Table '{table}' missing")
                return False
        
        # Check table structures
        for table in required_tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            print(f"Table '{table}' has {len(columns)} columns")
        
        print("Database verification complete!")
        return True
        
    except Exception as e:
        print(f"Error verifying database: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    print("Setting up Trivy Security Dashboard Database...")
    print("=" * 50)
    
    if create_database():
        print("\nVerifying database setup...")
        if verify_database():
            print("\nDatabase setup complete! Ready to run the dashboard.")
            print(f"Database location: {os.path.abspath(DATABASE_PATH)}")
        else:
            print("\nDatabase verification failed!")
    else:
        print("\nDatabase creation failed!")