"""
Logging and Reporting Module
Handles all logging, output formatting, and report generation
"""

import logging
import os
import json
import time
from datetime import datetime
from colorama import Fore, Style
import html

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}[{record.levelname}]{Style.RESET_ALL}"
        return super().format(record)

def setup_logger(verbose=False):
    """Setup logger with appropriate level and formatting"""
    logger = logging.getLogger('sqli_scanner')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = ColoredFormatter(
        '%(asctime)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or "results"
        self.ensure_output_dir()
        
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_json_report(self, results, filename=None):
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sqli_scan_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "scanner_version": "1.0.0",
                "total_targets": len(results.get('targets', [])),
                "vulnerabilities_found": len(results.get('vulnerabilities', []))
            },
            "results": results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def generate_html_report(self, results, filename=None):
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sqli_scan_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        html_content = self._create_html_template(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def generate_txt_report(self, results, filename=None):
        """Generate text report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sqli_scan_{timestamp}.txt"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self._create_text_report(results))
        
        return filepath
    
    def _create_html_template(self, results):
        """Create HTML report template"""
        vulnerabilities = results.get('vulnerabilities', [])
        targets = results.get('targets', [])
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #333; border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }}
        .summary-card h3 {{ margin: 0; color: #007bff; }}
        .summary-card p {{ margin: 10px 0 0 0; font-size: 24px; font-weight: bold; color: #333; }}
        .vulnerability {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .vulnerability.high {{ background: #f8d7da; border-color: #f5c6cb; }}
        .vulnerability.medium {{ background: #fff3cd; border-color: #ffeaa7; }}
        .vulnerability.low {{ background: #d1ecf1; border-color: #bee5eb; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .vuln-title {{ font-size: 18px; font-weight: bold; color: #333; }}
        .severity {{ padding: 4px 12px; border-radius: 20px; color: white; font-size: 12px; font-weight: bold; }}
        .severity.high {{ background-color: #dc3545; }}
        .severity.medium {{ background-color: #ffc107; color: #333; }}
        .severity.low {{ background-color: #17a2b8; }}
        .vuln-details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 10px; }}
        .code {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 14px; overflow-x: auto; }}
        .no-vulns {{ text-align: center; color: #28a745; font-size: 18px; padding: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SQL Injection Scan Report</h1>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Targets Scanned</h3>
                <p>{len(targets)}</p>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities Found</h3>
                <p>{len(vulnerabilities)}</p>
            </div>
            <div class="summary-card">
                <h3>High Risk</h3>
                <p>{len([v for v in vulnerabilities if v.get('severity') == 'high'])}</p>
            </div>
            <div class="summary-card">
                <h3>Medium Risk</h3>
                <p>{len([v for v in vulnerabilities if v.get('severity') == 'medium'])}</p>
            </div>
        </div>
        
        <h2>🔍 Vulnerability Details</h2>
        """
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low')
                html_template += f"""
        <div class="vulnerability {severity}">
            <div class="vuln-header">
                <div class="vuln-title">{html.escape(vuln.get('url', 'Unknown URL'))}</div>
                <span class="severity {severity}">{severity.upper()}</span>
            </div>
            <div class="vuln-details">
                <p><strong>Parameter:</strong> {html.escape(vuln.get('parameter', 'Unknown'))}</p>
                <p><strong>Method:</strong> {vuln.get('method', 'Unknown')}</p>
                <p><strong>Injection Type:</strong> {vuln.get('injection_type', 'Unknown')}</p>
                <p><strong>DBMS:</strong> {vuln.get('dbms', 'Unknown')}</p>
                <div class="code">
                    <strong>Payload:</strong><br>
                    {html.escape(vuln.get('payload', 'No payload recorded'))}
                </div>
                <div class="code">
                    <strong>Evidence:</strong><br>
                    {html.escape(vuln.get('evidence', 'No evidence recorded'))}
                </div>
            </div>
        </div>
                """
        else:
            html_template += '<div class="no-vulns">✅ No SQL injection vulnerabilities found!</div>'
        
        html_template += """
    </div>
</body>
</html>
        """
        
        return html_template
    
    def _create_text_report(self, results):
        """Create text report"""
        report = []
        report.append("=" * 60)
        report.append("SQL INJECTION SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        targets = results.get('targets', [])
        vulnerabilities = results.get('vulnerabilities', [])
        
        report.append("SUMMARY:")
        report.append(f"  Targets Scanned: {len(targets)}")
        report.append(f"  Vulnerabilities Found: {len(vulnerabilities)}")
        report.append(f"  High Risk: {len([v for v in vulnerabilities if v.get('severity') == 'high'])}")
        report.append(f"  Medium Risk: {len([v for v in vulnerabilities if v.get('severity') == 'medium'])}")
        report.append(f"  Low Risk: {len([v for v in vulnerabilities if v.get('severity') == 'low'])}")
        report.append("")
        
        if vulnerabilities:
            report.append("VULNERABILITIES FOUND:")
            report.append("-" * 40)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"\n{i}. {vuln.get('url', 'Unknown URL')}")
                report.append(f"   Severity: {vuln.get('severity', 'Unknown').upper()}")
                report.append(f"   Parameter: {vuln.get('parameter', 'Unknown')}")
                report.append(f"   Method: {vuln.get('method', 'Unknown')}")
                report.append(f"   Injection Type: {vuln.get('injection_type', 'Unknown')}")
                report.append(f"   DBMS: {vuln.get('dbms', 'Unknown')}")
                report.append(f"   Payload: {vuln.get('payload', 'No payload recorded')}")
                report.append(f"   Evidence: {vuln.get('evidence', 'No evidence recorded')}")
        else:
            report.append("✅ No SQL injection vulnerabilities found!")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)

class ScanLogger:
    """Logger for scan operations and results"""
    
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or "results"
        self.ensure_output_dir()
        self.requests_log = []
        self.vulnerabilities_log = []
        
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def log_request(self, url, method, params, payload, response_time, status_code, response_body):
        """Log HTTP request details"""
        request_data = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "method": method,
            "parameters": params,
            "payload": payload,
            "response_time": response_time,
            "status_code": status_code,
            "response_length": len(response_body) if response_body else 0,
            "response_body": response_body[:1000] if response_body else ""  # Truncate for storage
        }
        self.requests_log.append(request_data)
    
    def log_vulnerability(self, url, parameter, method, injection_type, payload, evidence, severity, dbms=None):
        """Log discovered vulnerability"""
        vuln_data = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "parameter": parameter,
            "method": method,
            "injection_type": injection_type,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "dbms": dbms
        }
        self.vulnerabilities_log.append(vuln_data)
    
    def save_logs(self):
        """Save all logs to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save requests log
        requests_file = os.path.join(self.output_dir, f"requests_{timestamp}.json")
        with open(requests_file, 'w', encoding='utf-8') as f:
            json.dump(self.requests_log, f, indent=2, ensure_ascii=False)
        
        # Save vulnerabilities log
        vulns_file = os.path.join(self.output_dir, f"vulnerabilities_{timestamp}.json")
        with open(vulns_file, 'w', encoding='utf-8') as f:
            json.dump(self.vulnerabilities_log, f, indent=2, ensure_ascii=False)
        
        return requests_file, vulns_file
