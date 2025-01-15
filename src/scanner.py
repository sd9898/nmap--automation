#!/usr/bin/env python3
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime
import logging
import sys
from typing import Dict, List, Optional, Set
import argparse
import subprocess

# Define directories
results_dir = 'results'
reports_dir = 'reports'

def generate_html_report(scan_results: Dict, target: str, reports_dir: str) -> Optional[str]:
    report_path = os.path.join(reports_dir, f"scan_report_{target.replace('.', '_')}.html")
    with open(report_path, 'w') as f:
        f.write("<html><head><title>Scan Report</title></head><body>")
        f.write(f"<h1>Scan Report for {target}</h1>")
        for scan_type, result in scan_results.items():
            f.write(f"<h2>{scan_type.capitalize()} Scan Results</h2>")
            f.write("<pre>")
            f.write(result)  # Assuming result is a string representation of the scan results
            f.write("</pre>")
        f.write("</body></html>")
    return report_path

def save_results_to_txt(scan_results: Dict, target: str, results_dir: str) -> Optional[str]:
    txt_path = os.path.join(results_dir, f"scan_results_{target.replace('.', '_')}.txt")
    with open(txt_path, 'w') as f:
        for scan_type, result in scan_results.items():
            f.write(f"{scan_type.capitalize()} Scan Results:\n")
            f.write(result)  # Assuming result is a string representation of the scan results
            f.write("\n\n")
    return txt_path

def print_scan_results(scan_results: Dict):
    for scan_type, result in scan_results.items():
        print(f"{scan_type.capitalize()} Scan Results:")
        root = ET.fromstring(result)
        for port in root.findall(".//port"):
            port_id = port.get("portid")
            state = port.find("state").get("state")
            service = port.find("service").get("name")
            print(f"Port {port_id}: {state} ({service})")
        print("\n")

def create_summary(scan_results: Dict) -> Dict:
    # ...existing code...
    pass

def perform_scan(target, timestamp):
    # Construct the Nmap command with -Pn option
    command = f"nmap -sS -Pn {target} -oX results/basic_{target.replace('.', '_')}_{timestamp}.xml"
    
    try:
        # Execute the command
        subprocess.run(command, shell=True, check=True)
        print(f"Scan completed for {target}. Results saved.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while performing the scan: {e}")

def main():
    parser = argparse.ArgumentParser(description='Generate HTML report from scan results')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--timestamp', help='Timestamp of scan results to process')
    
    args = parser.parse_args()
    
    # Setup directories
    results_dir = "results"
    reports_dir = "reports"
    
    # Check if results directory exists
    if not os.path.exists(results_dir):
        print(f"Error: Results directory '{results_dir}' not found.")
        print("Please run a scan first using scanner.py")
        sys.exit(1)
    
    # Create reports directory if it doesn't exist
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    # Find latest scan if timestamp not provided
    if not args.timestamp:
        files = os.listdir(results_dir)
        timestamps = set()
        target_formatted = args.target.replace('.', '_')
        
        for file in files:
            if file.startswith(f"basic_{target_formatted}_"):
                parts = file.split('_')
                if len(parts) >= 2:
                    timestamp = '_'.join(parts[-2:]).replace('.xml', '')
                    timestamps.add(timestamp)
        
        if not timestamps:
            print(f"No scan results found for target: {args.target}")
            print("Performing a new scan...")
            args.timestamp = "20230101_120000"  # Example timestamp, replace with actual timestamp logic
            results = perform_scan(args.target, args.timestamp)
        else:
            args.timestamp = sorted(timestamps)[-1]
            print(f"Using latest scan results with timestamp: {args.timestamp}")
    else:
        results = perform_scan(args.target, args.timestamp)

    # Load results
    scan_types = ['basic', 'comprehensive', 'udp', 'aggressive']
    results = {}

    for scan_type in scan_types:
        filename = f"{scan_type}_{args.target.replace('.', '_')}_{args.timestamp}.xml"
        filepath = os.path.join(results_dir, filename)
        
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    results[scan_type] = f.read()  # Read the XML content
                    print(f"Results loaded for {scan_type} scan.")
            except (IOError, Exception) as e:
                print(f"Error loading {filename}: {e}")

    if results:
        print("Scan results found and processed.")
        print_scan_results(results)  # Print results to command line
        txt_path = save_results_to_txt(results, args.target, results_dir)
        print(f"Results saved to text file at: {txt_path}")
    else:
        print("No scan results found.")

if __name__ == '__main__':
    main()
