#!/usr/bin/env python3
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging
import sys

class ScanReportGenerator:
    def __init__(self, results_dir: str = "results", reports_dir: str = "reports"):
        self.results_dir = results_dir
        self.reports_dir = reports_dir
        
        # Check if results directory exists
        if not os.path.exists(self.results_dir):
            print(f"Error: Results directory '{self.results_dir}' not found.")
            print("Please run a scan first using scanner.py")
            sys.exit(1)
            
        # Create reports directory if it doesn't exist
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        self.logger = logging.getLogger('ReportGenerator')

    def find_latest_scan(self, target: str) -> Optional[str]:
        """Find the most recent scan timestamp for a target"""
        try:
            files = os.listdir(self.results_dir)
            timestamps = set()
            target_formatted = target.replace('.', '_')
            
            for file in files:
                if file.startswith(f"basic_{target_formatted}_"):
                    # Extract timestamp from filename
                    parts = file.split('_')
                    if len(parts) >= 2:
                        timestamp = '_'.join(parts[-2:]).replace('.json', '')
                        timestamps.add(timestamp)
            
            if not timestamps:
                return None
                
            return sorted(timestamps)[-1]
            
        except Exception as e:
            print(f"Error finding latest scan: {str(e)}")
            return None

    def load_scan_results(self, target: str, timestamp: str) -> Dict:
        """Load all scan results for a specific target and timestamp"""
        scan_types = ['basic', 'comprehensive', 'udp', 'aggressive']
        results = {}
        
        try:
            for scan_type in scan_types:
                filename = f"{scan_type}_{target.replace('.', '_')}_{timestamp}.json"
                filepath = os.path.join(self.results_dir, filename)
                
                if os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        results[scan_type] = json.load(f)
                        
            return results
        except Exception as e:
            print(f"Error loading scan results: {str(e)}")
            return {}

    def generate_html_report(self, scan_results: Dict, target: str) -> Optional[str]:
        """Generate HTML report from scan results"""
        if not scan_results:
            print("No scan results to generate report from.")
            return None
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Nmap Scan Report - {target}</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        margin: 20px;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        background-color: white;
                        padding: 20px;
                        border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }}
                    h1, h2, h3 {{
                        color: #333;
                    }}
                    .scan-section {{
                        margin-bottom: 30px;
                        padding: 15px;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                    }}
                    .port-table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 10px;
                    }}
                    .port-table th, .port-table td {{
                        padding: 8px;
                        border: 1px solid #ddd;
                        text-align: left;
                    }}
                    .port-table th {{
                        background-color: #f8f9fa;
                    }}
                    .status-open {{
                        color: #28a745;
                        font-weight: bold;
                    }}
                    .status-closed {{
                        color: #dc3545;
                    }}
                    .summary-box {{
                        background-color: #f8f9fa;
                        padding: 15px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Nmap Scan Report</h1>
                    <div class="summary-box">
                        <h2>Scan Summary</h2>
                        <p><strong>Target:</strong> {target}</p>
                        <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    </div>
            """
            
            for scan_type, results in scan_results.items():
                html_content += f"""
                    <div class="scan-section">
                        <h2>{scan_type.capitalize()} Scan Results</h2>
                """
                
                if 'hostname' in results:
                    html_content += f"<p><strong>Hostname:</strong> {results['hostname']}</p>"
                if 'state' in results:
                    html_content += f"<p><strong>State:</strong> {results['state']}</p>"
                
                if 'ports' in results:
                    for protocol, ports in results['ports'].items():
                        html_content += f"""
                        <h3>{protocol.upper()} Ports</h3>
                        <table class="port-table">
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                            </tr>
                        """
                        
                        for port, info in ports.items():
                            state_class = "status-open" if info['state'] == 'open' else "status-closed"
                            html_content += f"""
                            <tr>
                                <td>{port}</td>
                                <td class="{state_class}">{info['state']}</td>
                                <td>{info['service']}</td>
                                <td>{info.get('product', '')} {info.get('version', '')}</td>
                            </tr>
                            """
                        
                        html_content += "</table>"
                
                if 'os_matches' in results and results['os_matches']:
                    html_content += """
                        <h3>OS Detection</h3>
                        <table class="port-table">
                            <tr>
                                <th>OS Name</th>
                                <th>Accuracy</th>
                            </tr>
                    """
                    
                    for os in results['os_matches']:
                        html_content += f"""
                            <tr>
                                <td>{os['name']}</td>
                                <td>{os['accuracy']}%</td>
                            </tr>
                        """
                    
                    html_content += "</table>"
                
                html_content += "</div>"
            
            html_content += """
                </div>
            </body>
            </html>
            """
            
            # Save the report
            report_path = os.path.join(self.reports_dir, f"report_{target.replace('.', '_')}_{timestamp}.html")
            with open(report_path, 'w') as f:
                f.write(html_content)
            
            return report_path
            
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Generate HTML report from scan results')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--timestamp', help='Timestamp of scan results to process')
    
    args = parser.parse_args()
    
    # Create report generator
    generator = ScanReportGenerator()
    
    # Find latest scan if timestamp not provided
    if not args.timestamp:
        args.timestamp = generator.find_latest_scan(args.target)
        if not args.timestamp:
            print(f"No scan results found for target: {args.target}")
            print("Please run a scan first using scanner.py")
            return
    
    # Load results and generate report
    results = generator.load_scan_results(args.target, args.timestamp)
    if results:
        report_path = generator.generate_html_report(results, args.target)
        if report_path:
            print(f"\nScan Summary for {args.target}:")
            print(f"HTML report generated: {report_path}")
            
            # Create and print summary
            summary = {
                'total_open_ports': 0,
                'open_ports_by_protocol': {},
                'detected_services': set(),
                'os_detection': []
            }
            
            for scan_type, scan_results in results.items():
                if 'ports' in scan_results:
                    for protocol, ports in scan_results['ports'].items():
                        if protocol not in summary['open_ports_by_protocol']:
                            summary['open_ports_by_protocol'][protocol] = []
                        
                        for port, info in ports.items():
                            if info['state'] == 'open':
                                summary['total_open_ports'] += 1
                                summary['open_ports_by_protocol'][protocol].append(int(port))
                                if info['service']:
                                    summary['detected_services'].add(info['service'])
                
                if 'os_matches' in scan_results and scan_results['os_matches']:
                    summary['os_detection'].extend(scan_results['os_matches'])
            
            print(f"\nTotal open ports: {summary['total_open_ports']}")
            for protocol, ports in summary['open_ports_by_protocol'].items():
                if ports:
                    print(f"\n{protocol.upper()} open ports: {len(ports)}")
                    print(f"Open ports: {', '.join(map(str, sorted(ports)))}")
            
            if summary['detected_services']:
                print(f"\nDetected services: {', '.join(sorted(summary['detected_services']))}")
            
            if summary['os_detection']:
                print("\nOS Detection:")
                for os in summary['os_detection']:
                    print(f"- {os['name']} (Accuracy: {os['accuracy']}%)")
    else:
        print("No scan results found or error loading results")

if __name__ == '__main__':
    import argparse
    main()