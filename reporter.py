import json
import time
from datetime import datetime
from pathlib import Path
from config import config

class ReportGenerator:
    def __init__(self):
        self.scan_id = int(time.time())
        
    def generate_console_report(self, results, scan_time, target_url=""):
        """Generate formatted console output"""
        report = f"""
╔══════════════════════════════════════════════════╗
║                 XSScan Scan Results              ║
╚══════════════════════════════════════════════════╝

📋 SCAN DETAILS:
────────────────
• Scan ID: {self.scan_id}
• Target: {target_url}
• Scan Time: {scan_time:.2f} seconds
• Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
• Vulnerabilities Found: {len(results)}

"""
        
        if results:
            report += "🎯 VULNERABILITIES FOUND:\n"
            report += "──────────────────────────\n"
            
            for i, vuln in enumerate(results, 1):
                report += f"\n🔓 VULNERABILITY #{i}:\n"
                report += f"   • Type: {vuln.get('type', 'Unknown')}\n"
                if vuln.get('parameter'):
                    report += f"   • Parameter: {vuln['parameter']}\n"
                report += f"   • Payload: {vuln.get('payload', 'Unknown')}\n"
                report += f"   • Detection Method: {vuln.get('detection_method', 'Unknown')}\n"
                if vuln.get('url'):
                    report += f"   • URL: {vuln['url']}\n"
                if vuln.get('evidence'):
                    report += f"   • Evidence: {vuln['evidence']}\n"
        else:
            report += "✅ No vulnerabilities found.\n"
            
        # Add summary
        if results:
            report += f"\n📊 SUMMARY:\n"
            report += f"───────────\n"
            report += f"• Total Vulnerabilities: {len(results)}\n"
            
            # Count by type
            by_type = {}
            for vuln in results:
                vuln_type = vuln.get('type', 'Unknown')
                by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            
            for vuln_type, count in by_type.items():
                report += f"• {vuln_type}: {count}\n"
                
            report += f"• Risk Level: {'HIGH' if len(results) > 0 else 'LOW'}\n"
            
        report += f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        return report
        
    def save_report(self, results, file_path, scan_time, target_url=""):
        """Save detailed report to file"""
        report_data = {
            'scan_id': self.scan_id,
            'timestamp': datetime.now().isoformat(),
            'target_url': target_url,
            'scan_duration': scan_time,
            'vulnerabilities_found': len(results),
            'vulnerabilities': results,
            'summary': self._generate_summary(results)
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
    def _generate_summary(self, results):
        """Generate vulnerability summary"""
        summary = {
            'total': len(results),
            'by_type': {},
            'by_method': {},
            'risk_level': 'LOW' if len(results) == 0 else 'HIGH'
        }
        
        for vuln in results:
            vuln_type = vuln.get('type', 'Unknown')
            detection_method = vuln.get('detection_method', 'Unknown')
            
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            summary['by_method'][detection_method] = summary['by_method'].get(detection_method, 0) + 1
            
        return summary